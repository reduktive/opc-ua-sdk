// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.9 - close-session flip (4.9f).
//
// What is pinned:
//   - close on an Activated session emits a CloseSessionResponse with Good
//     service_result and transitions the cross-strand observable
//     (is_activated()) to false.
//   - Double-close (close after close) emits BadSessionIdInvalid.
//   - terminate_for_shutdown on an Activated session does NOT throw and the
//     destructor runs cleanly without UAF (CS-H from runbook section 4.9).
//
// boost::asio::strand<boost::asio::any_io_executor>-rule section 7: close posts to the strand and signals via
// callback. The pin asserts the externally-observable post-condition (response delivered, is_activated()
// false) without inspecting the strand-internal mechanism.
//
// What is NOT pinned (deferred):
//   - terminate_for_shutdown firing in-flight CreateFlow / ActivateFlow /
//     per-request flows with BadSessionClosed (CS-E). Per runbook section 4.9 TODO
//     this is target-behaviour the pre-flip code does not yet deliver; the
//     pin is omitted until the human resolution lands.
//   - SubscriptionsPipeline close invocation (CS-G) - requires a fake
//     SubscriptionsPipeline observer.

#include <chrono>
#include <gtest/gtest.h>

#include "fake_session_dependencies.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_close_session_request.h"
#include "ua_close_session_response.h"
#include "ua_service_fault.h"

namespace ua::test::pins_4_9
{

namespace
{

class SessionClosePin : public ::testing::Test
{};

}  // namespace

// ---------------------------------------------------------------------------
// Pin: close on activated session emits CloseSessionResponse and clears
// is_activated().
// ---------------------------------------------------------------------------
TEST_F(SessionClosePin, CloseOnActivatedSessionEmitsResponseAndClearsActivated)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 400;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_responses(1);
  (void)h->take_response();

  ASSERT_TRUE(h->session->is_activated());

  CloseSessionRequest csReq;
  csReq.request_header().request_handle() = 401;
  h->session->close(3, std::move(csReq));

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* csResp = dynamic_cast<CloseSessionResponse*>(resp.second.get());
  ASSERT_NE(csResp, nullptr) << "expected CloseSessionResponse";
  EXPECT_TRUE(csResp->response_header().service_result().is_good());

  EXPECT_FALSE(h->session->is_activated());

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: double-close produces BadSessionIdInvalid.
// Source: ua_server_session.cpp:848-852.
// ---------------------------------------------------------------------------
// Re-enabled 2026-05-03 (MR2.5 Phase 3): production fix in
// `Session::create_and_send_service_fault` to fall back to mResponseMessages when no
// secure channel is attached (mirrors the success-path fallback used by close_internal,
// cancel, etc.).
// Covers SVR-SESS-006 (coverage-audit retag).
TEST_F(SessionClosePin, DoubleCloseProducesBadSessionIdInvalid)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 410;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_responses(1);
  (void)h->take_response();

  CloseSessionRequest cs1;
  cs1.request_header().request_handle() = 411;
  h->session->close(3, std::move(cs1));
  h->wait_for_responses(1);
  (void)h->take_response();

  CloseSessionRequest cs2;
  cs2.request_header().request_handle() = 412;
  h->session->close(4, std::move(cs2));
  h->wait_for_responses(1);
  auto resp = h->take_response();

  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(sf, nullptr) << "expected ServiceFault for double-close";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadSessionIdInvalid);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: terminate_for_shutdown on an activated session does not throw and the
// session destructs cleanly.
// ---------------------------------------------------------------------------
//
// CS-H from runbook section 4.9: "Drive close to completion; destruct the Session.
// Assert: no additional responses are emitted; no UAF (asserted under ASan)."
TEST_F(SessionClosePin, TerminateForShutdownIsCleanOnActivatedSession)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 420;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_responses(1);
  (void)h->take_response();

  // Calls terminate_for_shutdown internally; must not throw.
  EXPECT_NO_THROW(h->shutdown());
}

}  // namespace ua::test::pins_4_9
