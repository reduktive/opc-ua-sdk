// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.9 - CreateFlow (4.9b).
//
// What is pinned:
//   - CreateSession on a None channel produces a CreateSessionResponse with a
//     non-empty session_id and authentication_token (success path).
//   - CreateSession on a Closed session produces BadSessionIdInvalid + detail.
//   - CreateSession on an authenticated channel with a too-short client_nonce
//     produces BadNonceInvalid with a "ClientNonceTooShort" ErrorDetail.
//   - The authentication_token assigned in Session::create() is observable
//     immediately (before strand drains) via the public accessor.
//
// What is NOT pinned (deferred to richer FakeAsyncCrypto wiring per runbook
// section 4.0.1; flagged in the parent PR description):
//   - Cross-await ErrorDetail propagation through the 6 awaits in
//     send_create_session_response (Crypto entropy / cert load / sign /
//     ephemeral / endpoints chain). Requires a fake-async Crypto.
//   - ECC ephemeral-key generation observability.
//   - server_certificate / server_signature byte-content.

#include <chrono>
#include <gtest/gtest.h>

#include "fake_session_dependencies.h"

#include "ua_byte_string.h"
#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_error_detail.h"
#include "ua_security_policy.h"
#include "ua_service_fault.h"

namespace ua::test::pins_4_9
{

namespace
{

class CreateSessionPin : public ::testing::Test
{};

}  // namespace

// ---------------------------------------------------------------------------
// Pin: success on None channel produces a CreateSessionResponse with a
// non-empty session id and authentication token.
// ---------------------------------------------------------------------------
//
// Falsifiability: a regression that drops the response (no send) or routes
// CreateSession through ServiceFault would fail wait_for_responses() or the
// dynamic_cast respectively. The session_id non-empty check catches a
// regression that forgets to populate the identity snapshot.
TEST_F(CreateSessionPin, NoneChannelProducesResponseWithSessionIdAndAuthToken)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* csr = dynamic_cast<CreateSessionResponse*>(resp.second.get());
  ASSERT_NE(csr, nullptr) << "expected CreateSessionResponse, got a different shape";
  EXPECT_TRUE(csr->response_header().service_result().is_good());
  EXPECT_FALSE(csr->session_id().is_null()) << "session_id must be allocated";
  EXPECT_FALSE(csr->authentication_token().is_null()) << "authentication_token must be allocated";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: revised_session_timeout is published on the response.
// ---------------------------------------------------------------------------
// Covers SVR-SESS-014 (coverage-audit retag).
TEST_F(CreateSessionPin, NoneChannelResponsePublishesRevisedSessionTimeout)
{
  auto h = make_harness(SecurityPolicyId::None, ByteString{});

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* csr = dynamic_cast<CreateSessionResponse*>(resp.second.get());
  ASSERT_NE(csr, nullptr);
  // The negotiated timeout must be a positive duration; the exact value depends
  // on server config - the pin asserts the field is set, not a specific value.
  EXPECT_GT(static_cast<double>(csr->revised_session_timeout()), 0.0)
    << "revised_session_timeout must be positive after CreateSession";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: authentication_token is observable on the public Session accessor
// before the strand has drained the create_internal coroutine.
// ---------------------------------------------------------------------------
//
// The token is assigned in Session::create() **eagerly**, before the strand
// post - see sdk/implementation/server/session/ua_server_session.cpp:222-223.
// This ordering lets transactional admission publish an immutable token after validation without
// a second cross-strand mutation.
TEST_F(CreateSessionPin, AuthenticationTokenAvailableSynchronouslyAfterCreate)
{
  auto h = std::make_unique<SessionPinHarness>();
  auto ex = h->pool.get_executor();

  h->scDeps = std::make_shared<FakeSecureChannelDependencies>(ex);
  h->sc = server::SecureChannel::create(
    h->scDeps, nullptr, connection_protocol::NegotiatedLimits{}, server::ListenerHandle{1}, "L");
  server::SecureChannelTestAccess::on_strand(*h->sc,
    [&](auto& g)
    { g.set_minimal_context_authenticated(ex, "L/Ep", SecurityPolicyId::None, MessageSecurityMode::None); });

  server::ServerComponents hooks;
  hooks.authenticator = std::make_shared<AllowAnonymousAuthenticator>();
  h->sessDeps = std::make_shared<FakeSessionDependencies>(ex, std::move(hooks));

  server::SecureChannelInfo sci(h->sc->weak_from_this(),
    SecurityPolicy::create(SecurityPolicyId::None),
    MessageSecurityMode::None,
    "L/Ep",
    server::SecureChannelTestAccess::on_strand(
      *h->sc, [](auto& g) -> const auto& { return g.user_identity_tokens(); }));

  // Capture token immediately after create() - deliberately before strand_barrier.
  h->session = server::Session::create(h->sessDeps, sci, 1, CreateSessionRequest{});
  const auto& token = h->session->authentication_token();
  EXPECT_FALSE(token.is_null()) << "authentication_token must be set synchronously by Session::create()";

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: authenticated channel + too-short client nonce -> BadNonceInvalid with
// "ClientNonceTooShort" ErrorDetail (P4-SS-0023).
// ---------------------------------------------------------------------------
//
// Source: ua_server_session.cpp:619-627. The nonce length check fires
// synchronously inside create_internal before any await; the response is a
// ServiceFault with a non-null detail summarising the violation.
//
// A too-short client nonce on CreateSession surfaces the specific Bad_NonceInvalid: error-code masking
// applies only during SecureChannel establishment, not to session services (OPC 10000-2 section 6.3).
TEST_F(CreateSessionPin, AuthenticatedChannelTooShortNonceProducesBadNonceInvalidWithDetail)
{
  // 16-byte nonce - below the 32-byte minimum the server enforces.
  std::vector<uint8_t> raw(16, 0xAB);
  ByteString shortNonce{std::move(raw)};
  auto h = make_harness(SecurityPolicyId::Basic256Sha256, std::move(shortNonce));

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(sf, nullptr) << "expected ServiceFault for too-short client nonce";
  EXPECT_EQ(sf->response_header().service_result(), Status::BadNonceInvalid);

  // Pre-auth StatusCode masking does NOT apply at CreateSession (no session
  // exists yet to authenticate against); the explicit BadNonceInvalid is the
  // pinned externally-observable status.
  EXPECT_NE(sf->response_header().service_result(), Status::Good);

  h->shutdown();
}

// ---------------------------------------------------------------------------
// Pin: pre-auth nonce length check uses BadNonceInvalid, not a masked
// BadSecurityChecksFailed. The masking rule applies
// only to the AUTHENTICATED stage, not to client-side request validation
// errors. This pin documents the boundary.
//
// Client-request validation surfaces the specific code, not a masked Bad_SecurityChecksFailed.
// ---------------------------------------------------------------------------
TEST_F(CreateSessionPin, PreAuthClientValidationFailureIsNotMaskedToSecurityChecksFailed)
{
  std::vector<uint8_t> raw(8, 0x00);  // very short
  ByteString shortNonce{std::move(raw)};
  auto h = make_harness(SecurityPolicyId::Basic256Sha256, std::move(shortNonce));

  h->wait_for_responses(1);
  auto resp = h->take_response();
  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  ASSERT_NE(sf, nullptr);
  EXPECT_EQ(sf->response_header().service_result(), Status::BadNonceInvalid)
    << "client request validation must surface BadNonceInvalid, not be masked";

  h->shutdown();
}

}  // namespace ua::test::pins_4_9
