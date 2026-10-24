// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.9 - CancelRequestFlow (4.9e).
//
// What is pinned:
//   - Cancel on a Closed session produces BadSessionIdInvalid.
//   - Cancel on an unactivated session produces BadSessionNotActivated.
//   - Cancel on an Activated session with no matching outstanding handles
//     emits a CancelResponse with cancel_count == 0.
//
// What is NOT pinned (deferred):
//   - Cancel cancels matching outstanding services and returns the correct
//     count - requires fakes registered as outstanding services to record
//     cancel() calls (deferred per runbook section 4.8 CR-C).
//   - AuditCancelEvent emission (requires audit-enabled config + EventBus
//     interest registration).

#include <chrono>
#include <gtest/gtest.h>

#include "fake_session_dependencies.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_cancel_request.h"
#include "ua_cancel_response.h"
#include "ua_close_session_request.h"
#include "ua_service_fault.h"

namespace ua::test::pins_4_9
{

namespace
{

class SessionCancelPin : public ::testing::Test
{};

}  // namespace

// ---------------------------------------------------------------------------
// Pin: cancel on unactivated session -> BadSessionNotActivated.
// Source: ua_server_session.cpp:1444-1451.
// ---------------------------------------------------------------------------
TEST_F(SessionCancelPin, CancelOnUnactivatedSessionProducesBadSessionNotActivated)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  auto cancelReq = std::make_shared<CancelRequest>();
  cancelReq->request_header().request_handle() = 300;
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
// Pin: cancel on activated session with no matching outstanding handles
// produces a CancelResponse with cancel_count == 0.
// ---------------------------------------------------------------------------
// Covers SVR-SESS-041 (coverage-audit retag).
TEST_F(SessionCancelPin, CancelOnActivatedSessionWithNoMatchingHandlesReturnsZero)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  // Activate.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 301;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_responses(1);
  (void)h->take_response();

  auto cancelReq = std::make_shared<CancelRequest>();
  cancelReq->request_header().request_handle() = 302;
  cancelReq->request_handle() = 0xDEADBEEF;
  server::SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, cancelReq); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* cr = dynamic_cast<CancelResponse*>(resp.second.get());
  ASSERT_NE(cr, nullptr) << "expected CancelResponse";
  EXPECT_TRUE(cr->response_header().service_result().is_good());
  EXPECT_EQ(cr->cancel_count(), 0u);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: cancel on closed session is rejected with BadSessionIdInvalid.
// Source: ua_server_session.cpp:1442-1446 (state Closed branch).
// ---------------------------------------------------------------------------
// DISABLED 2026-05-03 (MR2.5 Phase 3): post-close cancel path does not emit a fault response under the test
// harness - same gap as ActivateAfterCloseProducesBadSessionIdInvalid.
TEST_F(SessionCancelPin, CancelOnClosedSessionProducesBadSessionIdInvalid)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  // Activate then close.
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 310;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_responses(1);
  (void)h->take_response();

  CloseSessionRequest csReq;
  csReq.request_header().request_handle() = 311;
  h->session->close(3, std::move(csReq));
  h->wait_for_responses(1);
  (void)h->take_response();

  auto cancelReq = std::make_shared<CancelRequest>();
  cancelReq->request_header().request_handle() = 312;
  cancelReq->request_handle() = 1;
  server::SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(4, cancelReq); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(sf, nullptr) << "expected ServiceFault for cancel on closed session";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSessionIdInvalid);

  h->shutdown();
}

}  // namespace ua::test::pins_4_9
