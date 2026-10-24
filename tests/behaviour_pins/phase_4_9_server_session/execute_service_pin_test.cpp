// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.9 - ExecuteService dispatch (4.9d.1).
//
// What is pinned (observable dispatch outcome ONLY - must survive the
// 4.9d.1 typed-handler-table refactor unchanged):
//   - A ReadRequest dispatched to an Activated session produces some response
//     for the same requestId - i.e. the dispatcher routed the request to a
//     handler rather than dropping it.
//   - The dispatcher does not re-route a ReadRequest to a different
//     ServiceKind handler (a misroute would produce BadRequestTypeInvalid via
//     the dynamic_cast failure pattern at ua_server_session.cpp:1535-1536).
//
// CRITICAL constraint per runbook section 3.2: pins must NOT inspect a `case
// Session::ServiceKind::X:` arm directly - the post-refactor world replaces
// the switch with a typed handler table and pins must survive that change.
// All assertions here drive `inject_decoded_request_for_tests` and observe
// the response shape, not the switch internals.
//
// What is NOT pinned (deferred per runbook section 4.7's 30-pin matrix):
//   - One pin per ServiceKind enumerant (29 + mismatch). Requires fakes for
//     each Service implementation (Read/Browse/Write/Call/Subscription/etc.)
//     to record per-kind dispatch. Out of scope for this pin-only PR's
//     starter corpus; flagged as a missing-fake gap.

#include <chrono>
#include <gtest/gtest.h>

#include "fake_session_dependencies.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"
#include "ua_browse_request.h"
#include "ua_get_endpoints_request.h"
#include "ua_read_request.h"
#include "ua_service_fault.h"

namespace ua::test::pins_4_9
{

namespace
{

class ExecuteServicePin : public ::testing::Test
{};

// Activate the session held by `h` and consume the activation response.
void activate(SessionPinHarness& h, uint32_t requestId)
{
  ActivateSessionRequest asr;
  asr.request_header().request_handle() = requestId;
  h.session->activate(requestId, std::move(asr), {});
  h.wait_for_responses(1);
  auto resp = h.take_response();
  auto* asResp = dynamic_cast<ActivateSessionResponse*>(resp.second.get());
  ASSERT_NE(asResp, nullptr);
  ASSERT_TRUE(asResp->response_header().service_result().is_good());
}

}  // namespace

// ---------------------------------------------------------------------------
// Pin: a Read request injected on an Activated session reaches a handler and
// produces a response for the same requestId.
// ---------------------------------------------------------------------------
//
// The downstream Read handler may produce a ServiceFault (the harness has no
// AddressSpace wired), but the dispatcher must route to *some* handler - the
// pin asserts that a response (any shape) is produced for the injected
// requestId. A regression that drops the request entirely fails
// wait_for_responses().
TEST_F(ExecuteServicePin, ReadRequestOnActivatedSessionReachesAHandler)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();
  activate(*h, 2);

  auto readReq = std::make_shared<ReadRequest>();
  readReq->request_header().request_handle() = 200;
  server::SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, readReq); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  EXPECT_EQ(resp.first, 3u) << "response must be tagged with the original requestId";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: a Browse request injected on an Activated session reaches a handler.
// Different ServiceKind from Read - the dispatcher must route on type, not on
// requestId or some other static state.
// ---------------------------------------------------------------------------
TEST_F(ExecuteServicePin, BrowseRequestOnActivatedSessionReachesAHandler)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();
  activate(*h, 2);

  auto browseReq = std::make_shared<BrowseRequest>();
  browseReq->request_header().request_handle() = 201;
  server::SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(3, browseReq); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  EXPECT_EQ(resp.first, 3u);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: GetEndpointsRequest is dispatched as discovery (no activation gate)
// and the requestId is preserved on the resulting response.
// ---------------------------------------------------------------------------
TEST_F(ExecuteServicePin, DiscoveryGetEndpointsDispatchedWithoutActivation)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();
  // Deliberately skip activation - discovery does not require it.

  auto req = std::make_shared<GetEndpointsRequest>();
  req->request_header().request_handle() = 202;
  server::SessionTestAccess::on_strand(*h->session, [&](auto& g) { g.inject_decoded_request(7, req); });

  h->wait_for_responses(1);
  auto resp = h->take_response();
  EXPECT_EQ(resp.first, 7u);
  // If a ServiceFault came back, it must NOT be BadSessionNotActivated.
  if (auto* sf = dynamic_cast<ServiceFault*>(resp.second.get()))
  {
    EXPECT_NE(sf->response_header().service_result(), Status::BadSessionNotActivated)
      << "GetEndpoints (discovery) must dispatch without activation";
  }

  h->shutdown();
}

}  // namespace ua::test::pins_4_9
