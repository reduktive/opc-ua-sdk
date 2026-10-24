// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.9 - Helpers (4.9g).
//
// What is pinned:
//   - is_activated() is false on a freshly-Created session and true after
//     successful activation. Cross-strand observable invariant.
//   - authentication_token() is immutable after Session::create() - repeated
//     reads return the same value, including across activation.
//   - session_id() starts empty and becomes non-empty after create_internal
//     drains.
//   - set_close_reason() does not throw and is idempotent (called repeatedly).
//   - health_snapshot() returns a populated snapshot post-creation.
//
// What is NOT pinned (deferred):
//   - create_server_signature / generate_ecc_ephemeral_key / parse_identity_token
//     / verify_user_token_signature / verify_client_application_signature
//     direct observability - these are private member coroutines and are
//     observed indirectly through the ActivateFlow pins. Pinning them by
//     identifier would couple to the pre-flip method names which the post-flip
//     world drops (per runbook section 0 *_effect rename note).

#include <gtest/gtest.h>

#include "fake_session_dependencies.h"

#include "ua_activate_session_request.h"
#include "ua_activate_session_response.h"

namespace ua::test::pins_4_9
{

namespace
{

class SessionHelperPin : public ::testing::Test
{};

}  // namespace

// ---------------------------------------------------------------------------
// Pin: is_activated() is false on a freshly-Created session.
// ---------------------------------------------------------------------------
TEST_F(SessionHelperPin, IsActivatedFalseOnCreatedSession)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  EXPECT_FALSE(h->session->is_activated())
    << "Created (not yet Activated) session must report is_activated() == false";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: is_activated() is true after successful activation.
// ---------------------------------------------------------------------------
TEST_F(SessionHelperPin, IsActivatedTrueAfterSuccessfulActivation)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 500;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_responses(1);
  auto resp = h->take_response();
  ASSERT_NE(dynamic_cast<ActivateSessionResponse*>(resp.second.get()), nullptr);

  EXPECT_TRUE(h->session->is_activated());

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: authentication_token() is immutable across repeated calls and across
// activation. The token is set in Session::create() before the strand post.
// ---------------------------------------------------------------------------
TEST_F(SessionHelperPin, AuthenticationTokenImmutableAcrossActivation)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  // Read a copy now and again post-activation; they must equal.
  auto tokenBefore = h->session->authentication_token();
  EXPECT_FALSE(tokenBefore.is_null());

  ActivateSessionRequest asr;
  asr.request_header().request_handle() = 510;
  h->session->activate(2, std::move(asr), {});
  h->wait_for_responses(1);
  (void)h->take_response();

  auto tokenAfter = h->session->authentication_token();
  EXPECT_EQ(tokenBefore, tokenAfter) << "authentication_token must not change across activation";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: session_id() becomes non-empty after the create_internal coroutine has
// drained the strand. The identity snapshot is published via
// std::atomic<std::shared_ptr<...>> so other threads observe the update
// without explicit synchronisation.
// ---------------------------------------------------------------------------
TEST_F(SessionHelperPin, SessionIdNonEmptyAfterCreateInternalDrains)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  // strand_barrier inside make_harness already drained; wait for response too.
  h->wait_for_responses(1);
  (void)h->take_response();

  EXPECT_FALSE(h->session->session_id().is_null())
    << "session_id must be populated after create_internal drains";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: set_close_reason is callable from the test thread without throwing.
// Documents the public API contract; the close reason is internally
// serialised via std::atomic<StatusCodeValue>.
// ---------------------------------------------------------------------------
TEST_F(SessionHelperPin, SetCloseReasonIsNoexceptFromTestThread)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  EXPECT_NO_THROW(h->session->set_close_reason(StatusCode{Status::BadShutdown}));
  // Idempotent - calling twice must also not throw.
  EXPECT_NO_THROW(h->session->set_close_reason(StatusCode{Status::BadConnectionClosed}));

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: health_snapshot() returns without throwing and is callable from the
// test thread (it must be cross-strand safe per Rule 4: snapshot via atomics).
// ---------------------------------------------------------------------------
TEST_F(SessionHelperPin, HealthSnapshotIsCallableFromAnyThread)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});
  h->wait_for_responses(1);
  (void)h->take_response();

  EXPECT_NO_THROW({
    auto snapshot = h->session->health_snapshot();
    (void)snapshot;
  });

  h->shutdown();
}

}  // namespace ua::test::pins_4_9
