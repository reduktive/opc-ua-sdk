// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Phase-1 demonstration tests for the MisbehavingServer fixture (semantic Response& layer).
///
/// These are RED-first, real-loopback integration tests that drive a real client through the
/// adversarial secure-channel paths produced by a real server mutating its own responses:
///   - Row A: the fixture mechanism itself (service-result stamping), with a falsifiability control.
///   - Row B: CL-SC-015 - serverNonce of the wrong length is rejected.
///   - Row C: CL-SC-016 - serverNonce reused on renewal is rejected.
///
/// Each test is bounded: every client operation carries an explicit timeout, every wait uses a
/// deadline, and each harness drains its pool with a timeout on teardown, so a hang FAILS rather than
/// wedging the suite.

#include <gtest/gtest.h>

#include "misbehaving_server.h"

#include "ua_activate_session_request.h"
#include "ua_application_configuration.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_close_session_request.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_create_session_response.h"
#include "ua_create_session_request.h"
#include "ua_node_id.h"
#include "ua_read_request.h"
#include "ua_read_value_id.h"
#include "ua_write_request.h"
#include "ua_write_value.h"
#include "ua_reconnect_policy.h"
#include "ua_redundancy_manager.h"
#include "ua_variable_id.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_crypto_types.h"
#include "ua_message_security_mode.h"
#include "ua_signature_data.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_endpoint_description.h"
#include "ua_user_identity.h"
#include "ua_user_token_policy.h"
#include "ua_user_token_type.h"
#include "ua_issued_identity_token.h"
#include "ua_to_string.h"
#include "test_utilities.h"

#include <atomic>
#include <cstdint>
#include <vector>

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <thread>

#include "test_components.h"
using namespace std::chrono_literals;
using ua::test_helpers::MisbehavingServer;
using ua::test_helpers::OpnNonceContext;

namespace
{

// A client bound to a MisbehavingServer's crypto + client certificate store, on its own
// multi-threaded pool. Drains the pool on teardown so a leaked timer/handler surfaces as a failure.
class ClientHarness
{
public:
  explicit ClientHarness(MisbehavingServer& server)
  {
    auto appCfg = ua::test_utils::create_test_config();
    const auto clientStore = server.client_certificate_store();
    const auto ownCertificates = clientStore->try_get_application_certificates_sync();
    if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
        ownCertificates.value().front().certificate)
    {
      const auto sanUris = ownCertificates.value().front().certificate->san_uris();
      if (!sanUris.empty())
        appCfg.application_description_part().applicationUri = sanUris.front();
    }
    ua::client::CreateConfig cfg{
      .identity = ua::ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    mClient.emplace(ua::client::Client::create(mThreadPool.executor(),
      std::move(cfg),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = clientStore,
        .logLevel = ua::LogLevel::Warning}));
  }

  ~ClientHarness()
  {
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  ClientHarness(const ClientHarness&) = delete;
  ClientHarness& operator=(const ClientHarness&) = delete;

  ua::client::Client& client()
  {
    return *mClient;
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<ua::client::Client> mClient;
};

// Open an unauthenticated (None) channel and read its GetEndpoints response header serviceResult.
ua::StatusCode get_endpoints_service_result(
  ua::client::Client& client, const std::string& endpointUrl, ua::StatusCode& openStatus)
{
  ua::client::CoreClient::OpenChannelConfig openCfg;
  openCfg.endpointUrl = endpointUrl;
  openCfg.timeout = 5000ms;
  auto openResult = client.core().try_open_channel_sync(openCfg);
  openStatus = openResult.status_code();
  if (openResult.is_bad())
    return openResult.status_code();

  auto channel = std::move(openResult).value();

  ua::GetEndpointsRequest request;
  request.request_header().timeout_hint() = 5000;
  request.endpoint_url() = endpointUrl;
  auto response = channel.try_get_endpoints_sync(request);

  channel.try_close_sync();

  if (response.is_bad())
    return response.status_code();
  return response.value().response_header().service_result();
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Row A - fixture mechanism self-test (not a requirement row; it cites no requirement).
//
// set_service_result stamps ResponseHeader.serviceResult on service responses. A mutated server
// returns the stamped status; an identical server WITHOUT the mutator returns the real Good result.
//
// Falsifiability: the only difference between `mutated` and `control` is the single
// set_service_result() call. If that call were a no-op, or if the interceptor never fired, the
// mutated assertion (== Bad_UserAccessDenied) would fail. If the mutator's scope leaked onto a server
// that never armed it, the control assertion (== Good) would fail. The two channels opened on the
// mutated server further show per_channel() installs on EACH new channel.
// ---------------------------------------------------------------------------------------------
TEST(MisbehavingServerFixture, ServiceResultStampedOnEachMutatedChannel)
{
  MisbehavingServer mutated;
  mutated.per_channel().set_service_result(ua::StatusCode{ua::Status::BadUserAccessDenied});

  MisbehavingServer control;  // identical, but set_service_result is never called

  ClientHarness mutatedClient(mutated);
  ClientHarness controlClient(control);

  // Two distinct channels on the mutated server: per_channel() must stamp both.
  ua::StatusCode open1{ua::Status::Good};
  ua::StatusCode open2{ua::Status::Good};
  auto channel1Result =
    get_endpoints_service_result(mutatedClient.client(), mutated.endpoint_url_none(), open1);
  auto channel2Result =
    get_endpoints_service_result(mutatedClient.client(), mutated.endpoint_url_none(), open2);

  ASSERT_TRUE(open1.is_good()) << "mutated channel 1 should still open (OPN is not stamped)";
  ASSERT_TRUE(open2.is_good()) << "mutated channel 2 should still open (OPN is not stamped)";
  EXPECT_EQ(channel1Result, ua::StatusCode{ua::Status::BadUserAccessDenied});
  EXPECT_EQ(channel2Result, ua::StatusCode{ua::Status::BadUserAccessDenied});

  // Control server (no mutator): the SAME request/code path yields the server's real Good result.
  ua::StatusCode openControl{ua::Status::Good};
  auto controlResult =
    get_endpoints_service_result(controlClient.client(), control.endpoint_url_none(), openControl);
  ASSERT_TRUE(openControl.is_good()) << "control channel should open";
  EXPECT_EQ(controlResult, ua::StatusCode{ua::Status::Good})
    << "falsifiability: without the mutator the identical request returns Good";

  EXPECT_GT(mutated.interceptor_fire_count(), 0u) << "the response interceptor must have fired";

  // The control server's interceptor also fires (per_channel installs it), yet its result is Good -
  // proving it is the mutator, not the mere presence of an interceptor, that changes the outcome.
  EXPECT_GT(control.interceptor_fire_count(), 0u);
  EXPECT_FALSE(mutated.last_mutator_error().has_value()) << "no mutator should have thrown";
}

// ---------------------------------------------------------------------------------------------
// Finding 1 (section 3.1) - the interceptor install must NOT block a worker.
//
// The install runs inside set_on_secure_channel_available, which executes on a server pool worker. If
// it blocked that worker on a same-strand post (the previous on_strand path), a single-threaded
// server would have no free worker to service the post, so the channel would never open and the pool
// would never drain - a permanent deadlock. This test forces a SINGLE-threaded server executor and
// opens one channel: it must still open cleanly and the interceptor must still fire.
//
// RED-first: before the non-blocking-install fix, this test deadlocks (the open times out and the
// teardown drain hangs). After the fix it passes deterministically.
// ---------------------------------------------------------------------------------------------
TEST(MisbehavingServerFixture, InterceptorInstallDoesNotDeadlockSingleThreadedExecutor)
{
  MisbehavingServer server(MisbehavingServer::Config{}, /*serverThreadCount=*/std::size_t{1});

  ClientHarness clientHarness(server);

  ua::StatusCode open{ua::Status::Good};
  auto result = get_endpoints_service_result(clientHarness.client(), server.endpoint_url_none(), open);

  EXPECT_TRUE(open.is_good())
    << "a single-threaded server must open a channel: the interceptor install must be non-blocking";
  EXPECT_EQ(result, ua::StatusCode{ua::Status::Good})
    << "the real (unmutated) GetEndpoints result must come through on the single worker";
  EXPECT_GT(server.interceptor_fire_count(), 0u)
    << "the interceptor must still install and fire on the single worker";
}

// ---------------------------------------------------------------------------------------------
// Finding 2 (section 3.1) - raw mutators COMPOSE; they must not share one overwritten slot.
//
// Two mutators are registered through DIFFERENT setters - set_service_result (effect 1: stamp the
// serviceResult) and set_response_mutator (effect 2: clear the endpoints array). Both effects must
// reach the client on the same GetEndpoints response.
//
// RED-first: before the composition fix, the five raw-mutator setters shared one slot, so the second
// setter silently overwrote the first. Only effect 2 would survive and the serviceResult assertion
// (effect 1) would fail.
// ---------------------------------------------------------------------------------------------
TEST(MisbehavingServerFixture, RawMutatorsComposeInsteadOfOverwriting)
{
  MisbehavingServer server;
  server.per_channel().set_service_result(ua::StatusCode{ua::Status::BadUserAccessDenied});  // effect 1
  server.set_response_mutator(  // effect 2
    [](ua::Response& response)
    {
      if (auto* endpointsResponse = dynamic_cast<ua::GetEndpointsResponse*>(response.second.get()))
        endpointsResponse->endpoints().clear();
    });

  ClientHarness clientHarness(server);

  ua::client::CoreClient::OpenChannelConfig openCfg;
  openCfg.endpointUrl = server.endpoint_url_none();
  openCfg.timeout = 5000ms;
  auto openResult = clientHarness.client().core().try_open_channel_sync(openCfg);
  ASSERT_TRUE(openResult.is_good()) << ua::to_string(openResult.status_code());
  auto channel = std::move(openResult).value();

  ua::GetEndpointsRequest request;
  request.request_header().timeout_hint() = 5000;
  request.endpoint_url() = server.endpoint_url_none();
  auto response = channel.try_get_endpoints_sync(request);
  channel.try_close_sync();

  ASSERT_TRUE(response.is_good()) << "the response body is delivered even with a stamped serviceResult: "
                                  << ua::to_string(response.status_code());
  EXPECT_EQ(
    response.value().response_header().service_result(), ua::StatusCode{ua::Status::BadUserAccessDenied})
    << "effect 1 (set_service_result) must survive composition with a later set_response_mutator";
  EXPECT_TRUE(response.value().endpoints().empty())
    << "effect 2 (set_response_mutator clearing endpoints) must also survive composition";
  EXPECT_FALSE(server.last_mutator_error().has_value()) << "no composed mutator should have thrown";
}

// ---------------------------------------------------------------------------------------------
// Row B - CL-SC-015: serverNonce length must match the SecurityPolicy nonce length.
//
// Two negative cases on a Basic256Sha256 SignAndEncrypt channel, plus a positive control:
//   - truncated to 16 bytes (< the required 32) - caught by the policy-independent length floor; and
//   - padded to 48 bytes (> 32) - clears the floor, so it exercises the policy-length EQUALITY check
//     that CL-SC-015 actually mandates (the 16-byte case alone does not).
// Both must be rejected by the real client with Bad_NonceInvalid. A control server that leaves the
// nonce untouched opens Good.
// ---------------------------------------------------------------------------------------------
// @verifies CL-SC-015
// @relation(CL-SC-015, scope=function)
TEST(MisbehavingServerSecureChannel, ServerNonceWrongLengthRejected)
{
  MisbehavingServer badServer;
  badServer.mutate_server_nonce(
    [](const OpnNonceContext& context)
    {
      auto nonce = context.current;
      nonce.resize(16);  // 16 < 32 required for Basic256Sha256 -> Bad_NonceInvalid
      return nonce;
    });

  ClientHarness badClient(badServer);

  ua::client::CoreClient::OpenChannelConfig badCfg;
  badCfg.endpointUrl = badServer.endpoint_url_sign_encrypt();
  badCfg.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  badCfg.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  badCfg.serverCertificate = badServer.server_certificate();
  badCfg.timeout = 5000ms;
  auto badResult = badClient.client().core().try_open_channel_sync(badCfg);

  EXPECT_TRUE(badResult.is_bad()) << "a truncated serverNonce must be rejected";
  EXPECT_EQ(badResult.status_code(), ua::StatusCode{ua::Status::BadNonceInvalid});

  // Over-length negative case - exercises the CL-SC-015 policy-length EQUALITY branch, not the
  // policy-independent "< 32" floor. A 48-byte nonce clears the floor (48 >= 32), so it can only be
  // rejected by the check that the length EQUALS the policy nonce length (32 for Basic256Sha256).
  // The 16-byte case above is caught by the floor and does NOT prove the equality branch; this case
  // does. Falsifiable: delete the equality branch and a 48-byte nonce would be wrongly accepted.
  MisbehavingServer overLengthServer;
  overLengthServer.mutate_server_nonce(
    [](const OpnNonceContext& context)
    {
      auto nonce = context.current;
      nonce.resize(48);  // 48 > 32: passes the floor, fails the policy-length equality check
      return nonce;
    });

  ClientHarness overLengthClient(overLengthServer);

  ua::client::CoreClient::OpenChannelConfig overLengthCfg;
  overLengthCfg.endpointUrl = overLengthServer.endpoint_url_sign_encrypt();
  overLengthCfg.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  overLengthCfg.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  overLengthCfg.serverCertificate = overLengthServer.server_certificate();
  overLengthCfg.timeout = 5000ms;
  auto overLengthResult = overLengthClient.client().core().try_open_channel_sync(overLengthCfg);

  EXPECT_TRUE(overLengthResult.is_bad()) << "an over-length (48-byte) serverNonce must be rejected";
  EXPECT_EQ(overLengthResult.status_code(), ua::StatusCode{ua::Status::BadNonceInvalid});

  // Control: untouched nonce opens cleanly.
  MisbehavingServer goodServer;
  ClientHarness goodClient(goodServer);

  ua::client::CoreClient::OpenChannelConfig goodCfg;
  goodCfg.endpointUrl = goodServer.endpoint_url_sign_encrypt();
  goodCfg.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  goodCfg.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  goodCfg.serverCertificate = goodServer.server_certificate();
  goodCfg.timeout = 5000ms;
  auto goodResult = goodClient.client().core().try_open_channel_sync(goodCfg);

  EXPECT_TRUE(goodResult.is_good()) << "falsifiability: an untouched serverNonce opens Good (status="
                                    << ua::to_string(goodResult.status_code()) << ")";
  if (goodResult.is_good())
    goodResult.value().try_close_sync();
}

// ---------------------------------------------------------------------------------------------
// Row C - CL-SC-016: a new serverNonce shall be generated for each renewal; reuse must be rejected.
//
// A short-lifetime SignAndEncrypt channel opens (Issue), the fixture records the Issue nonce, then on
// the renewal OPN response the fixture replays that Issue nonce. The real client must reject the
// renewal with Bad_NonceInvalid and close the channel (surfaced via mOnChannelError). A control server
// that lets the server generate a fresh nonce on renewal renews cleanly (no channel error).
// ---------------------------------------------------------------------------------------------
// @verifies CL-SC-016
// @relation(CL-SC-016, scope=function)
TEST(MisbehavingServerSecureChannel, ServerNonceReusedOnRenewalRejected)
{
  std::mutex mutex;
  std::condition_variable condition;
  bool errorFired{false};
  ua::StatusCode errorStatus{ua::Status::Good};

  MisbehavingServer server(
    MisbehavingServer::Config{.secureChannelMinimumLifetime = 2000ms, .certificateScenario = std::nullopt});
  server.mutate_server_nonce(
    [](const OpnNonceContext& context)
    {
      // Issue (index 1): pass the real nonce through (client stores it; fixture records it).
      // Renewal (index >= 2): replay the recorded Issue nonce -> reuse -> client must reject.
      return context.opnResponseIndex >= 2 ? context.firstIssueNonce : context.current;
    });

  ClientHarness harness(server);

  ua::client::CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = server.endpoint_url_sign_encrypt();
  cfg.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = server.server_certificate();
  cfg.requestedLifetime = 2000ms;
  cfg.timeout = 5000ms;
  cfg.onChannelError = [&](ua::VoidResult result)
  {
    {
      std::lock_guard lock(mutex);
      errorFired = true;
      errorStatus = result.status_code();
    }
    condition.notify_one();
  };

  auto openResult = harness.client().core().try_open_channel_sync(cfg);
  ASSERT_TRUE(openResult.is_good()) << "the initial (Issue) open must succeed: "
                                    << ua::to_string(openResult.status_code());
  auto channel = std::move(openResult).value();

  // Renewal fires at ~75% of the 2000ms revised lifetime (~1.5s); the replayed nonce then trips
  // Bad_NonceInvalid and closes the channel.
  {
    std::unique_lock lock(mutex);
    ASSERT_TRUE(condition.wait_for(lock, 15s, [&] { return errorFired; }))
      << "renewal reuse must surface a channel error within the deadline";
  }
  EXPECT_EQ(errorStatus, ua::StatusCode{ua::Status::BadNonceInvalid});

  channel.try_close_sync();
}

// Positive control for CL-SC-016: a fresh distinct nonce on each renewal renews cleanly.
TEST(MisbehavingServerSecureChannel, ServerNonceFreshOnRenewalRenewsCleanly)
{
  std::mutex mutex;
  std::condition_variable condition;
  bool errorFired{false};
  ua::StatusCode errorStatus{ua::Status::Good};

  // No nonce mutation: the real server generates a fresh, distinct nonce on renewal.
  MisbehavingServer server(
    MisbehavingServer::Config{.secureChannelMinimumLifetime = 2000ms, .certificateScenario = std::nullopt});

  ClientHarness harness(server);

  ua::client::CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = server.endpoint_url_sign_encrypt();
  cfg.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = server.server_certificate();
  cfg.requestedLifetime = 2000ms;
  cfg.timeout = 5000ms;
  cfg.onChannelError = [&](ua::VoidResult result)
  {
    {
      std::lock_guard lock(mutex);
      errorFired = true;
      errorStatus = result.status_code();
    }
    condition.notify_one();
  };

  auto openResult = harness.client().core().try_open_channel_sync(cfg);
  ASSERT_TRUE(openResult.is_good()) << ua::to_string(openResult.status_code());
  auto channel = std::move(openResult).value();

  // Observe the FIRST renewal (the 2nd OPN response on the channel, at ~75% of the 2s lifetime) and
  // confirm it is accepted with the fresh, distinct server nonce. We break as soon as the renewal is
  // observed: at a 2s lifetime, sustained token rotation eventually trips an unrelated
  // BadSecureChannelTokenUnknown, so this test's claim is specifically "a fresh nonce on renewal is
  // NOT rejected as reuse (BadNonceInvalid)", not "the channel survives forever".
  bool renewalObserved = false;
  const auto deadline = std::chrono::steady_clock::now() + 8s;
  while (std::chrono::steady_clock::now() < deadline)
  {
    {
      std::lock_guard lock(mutex);
      if (errorFired)
        break;
    }
    // With no service traffic, every intercepted response on this channel is an OPN response; a fire
    // count >= 2 therefore means the Issue plus at least one renewal have been processed.
    if (server.interceptor_fire_count() >= 2)
    {
      renewalObserved = true;
      break;
    }
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_TRUE(renewalObserved) << "a renewal (2nd OPN) must occur so the positive case is not vacuous";
  {
    std::lock_guard lock(mutex);
    EXPECT_FALSE(errorFired) << "a fresh nonce on renewal must be accepted, not rejected (got "
                             << ua::to_string(errorStatus) << ")";
  }

  channel.try_close_sync();
}

// ---------------------------------------------------------------------------------------------
// CL-SESS-004 - the client CRYPTOGRAPHICALLY verifies the CreateSession serverSignature (over
// clientCert || clientNonce). A present, valid-length but TAMPERED signature (one byte flipped) must be
// rejected - only real verification fails this; a presence-only check would pass it - and the client must
// NOT proceed to ActivateSession. The secured channel itself opens cleanly (the tamper is at CreateSession).
// Falsifiable: a client that skipped verification would create the session Good and emit ActivateSession.
// ---------------------------------------------------------------------------------------------
// @verifies CL-SESS-004
// @relation(CL-SESS-004, scope=function)
TEST(MisbehavingServerSecureChannel, TamperedServerSignatureRejectedNoActivate)
{
  MisbehavingServer server;

  server.set_response_mutator(
    [](ua::Response& response)
    {
      auto* createResponse = dynamic_cast<ua::CreateSessionResponse*>(response.second.get());
      if (createResponse == nullptr)
        return;
      const auto& original = createResponse->server_signature().signature();
      if (original.empty())
        return;
      std::vector<std::uint8_t> bytes(original.begin(), original.end());
      bytes[0] = static_cast<std::uint8_t>(bytes[0] ^ 0xFFU);  // valid length, tampered content
      createResponse->server_signature().signature() = ua::ByteString{bytes};
    });

  auto sawActivate = std::make_shared<std::atomic<bool>>(false);
  server.set_request_observer(
    [sawActivate](const ua::Structure& request)
    {
      if (dynamic_cast<const ua::ActivateSessionRequest*>(&request) != nullptr)
        sawActivate->store(true);
    });

  ClientHarness harness(server);

  ua::client::CoreClient::OpenChannelConfig openCfg;
  openCfg.endpointUrl = server.endpoint_url_sign_encrypt();
  openCfg.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  openCfg.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  openCfg.serverCertificate = server.server_certificate();
  openCfg.timeout = 5000ms;
  auto openResult = harness.client().core().try_open_channel_sync(openCfg);
  ASSERT_TRUE(openResult.is_good())
    << "the secured channel itself must open (the tamper is at CreateSession): "
    << ua::to_string(openResult.status_code());
  auto channel = std::move(openResult).value();

  ua::client::SecureChannel::CreateSessionConfig sessionCfg;
  sessionCfg.sessionName = "CL_SESS_004_tampered_sig";
  auto sessionResult = channel.try_create_session_sync(sessionCfg);

  EXPECT_TRUE(sessionResult.is_bad())
    << "a tampered serverSignature must fail CreateSession cryptographically";
  EXPECT_EQ(sessionResult.status_code(), ua::StatusCode{ua::Status::BadApplicationSignatureInvalid});
  EXPECT_FALSE(sawActivate->load())
    << "no ActivateSession may be emitted once CreateSession signature verification fails";

  channel.try_close_sync();
}

// ---------------------------------------------------------------------------------------------
// CL-SC-012 - OPC 10000-4 section 5.6.2 (P4-0004, SHALL): the ApplicationInstanceCertificate returned in
// CreateSessionResponse MUST be the same certificate the secure channel was opened against. A server that
// returns a DIFFERENT certificate in CreateSession is substituting identity mid-handshake; the client must
// reject the session and NOT emit ActivateSession. The secured channel opens cleanly (the substitution is
// in the CreateSession body). This exercises the whole production path the ComplianceSecureChannel fixture
// could not (it cannot intercept a service body - hence its P4_0004 negative was skipped): the
// MisbehavingServer response mutator swaps the CreateSession serverCertificate to a differing DER.
// Falsifiable AND discriminating: a client that skipped the continuity check would fail LATER at signature
// validation (BadApplicationSignatureInvalid, the substitute key not matching the real signature) or reach
// Active; this asserts the earlier, distinct BadSecurityChecksFailed, proving the continuity check fired.
// @verifies CL-SC-012
// @verifies CL-SESS-003
// @relation(CL-SC-012, CL-SESS-003, scope=function)
TEST(MisbehavingServerSecureChannel, CertMismatchBetweenChannelAndCreateSessionRejected)
{
  MisbehavingServer server;

  server.set_response_mutator(
    [](ua::Response& response)
    {
      auto* createResponse = dynamic_cast<ua::CreateSessionResponse*>(response.second.get());
      if (createResponse == nullptr)
        return;
      const auto& original = createResponse->server_certificate();
      if (original.empty())
        return;
      std::vector<std::uint8_t> bytes(original.begin(), original.end());
      bytes[0] = static_cast<std::uint8_t>(bytes[0] ^ 0xFFU);  // a DIFFERENT DER than the channel cert
      createResponse->server_certificate() = ua::ByteString{bytes};
    });

  auto sawActivate = std::make_shared<std::atomic<bool>>(false);
  server.set_request_observer(
    [sawActivate](const ua::Structure& request)
    {
      if (dynamic_cast<const ua::ActivateSessionRequest*>(&request) != nullptr)
        sawActivate->store(true);
    });

  ClientHarness harness(server);

  ua::client::CoreClient::OpenChannelConfig openCfg;
  openCfg.endpointUrl = server.endpoint_url_sign_encrypt();
  openCfg.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  openCfg.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  openCfg.serverCertificate = server.server_certificate();
  openCfg.timeout = 5000ms;
  auto openResult = harness.client().core().try_open_channel_sync(openCfg);
  ASSERT_TRUE(openResult.is_good())
    << "the secured channel itself must open (the substitution is at CreateSession): "
    << ua::to_string(openResult.status_code());
  auto channel = std::move(openResult).value();

  ua::client::SecureChannel::CreateSessionConfig sessionCfg;
  sessionCfg.sessionName = "CL_SC_012_cert_mismatch";
  auto sessionResult = channel.try_create_session_sync(sessionCfg);

  EXPECT_TRUE(sessionResult.is_bad())
    << "a CreateSession certificate differing from the channel certificate must fail (P4-0004)";
  EXPECT_EQ(sessionResult.status_code(), ua::StatusCode{ua::Status::BadSecurityChecksFailed});
  EXPECT_FALSE(sawActivate->load())
    << "no ActivateSession may be emitted once the certificate-continuity check fails";

  channel.try_close_sync();
}

// ---------------------------------------------------------------------------------------------
// CL-REDUN-001 was verified here by `MisbehavingServerRedundancy.NoneRedundancySupportReadThenSkips-
// Manager`, which armed the redundancy manager through `ConnectionConfig::enableRedundancy` and
// observed it read `Server.ServerRedundancy.RedundancySupport` after activate.
//
// **That test was removed because the reachability it verified was deliberately withdrawn**, not
// because it broke: the client redundancy surface is unexported for the initial release, so no
// public configuration can arm the manager (client_design.md section 8.11.10). Its replacement is
// `ConnectPlan.NoPublicConfigCanArmTheRedundancyEngine`, which pins the opposite contract - that no
// public config reaches the engine at all - and the engine's own behaviour keeps its 109 unit tests
// under tests/unit/client/redundancy/. Restore this test alongside the public accessor if the facet
// is ever claimed.
// ---------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------
// CL-AUDIT-001 - a managed tier-2 Connection applies the configured auditEntryId provider to a
// caller-issued tier-1 Read immediately before the request reaches the real server.
// ---------------------------------------------------------------------------------------------
// @verifies CL-AUDIT-001
// @verifies CL-AUDIT-002
// @relation(CL-AUDIT-001, CL-AUDIT-002, scope=function)
TEST(MisbehavingServerAudit, AuditEntryIdProviderReachesWire)
{
  MisbehavingServer server;
  auto sawCreateSessionAudit = std::make_shared<std::atomic<bool>>(false);
  auto sawActivateSessionAudit = std::make_shared<std::atomic<bool>>(false);
  auto sawAuditEntryId = std::make_shared<std::atomic<bool>>(false);
  auto sawReadWithoutAudit = std::make_shared<std::atomic<bool>>(false);
  auto sawCloseSessionAudit = std::make_shared<std::atomic<bool>>(false);
  server.set_request_observer(
    [sawCreateSessionAudit,
      sawActivateSessionAudit,
      sawAuditEntryId,
      sawReadWithoutAudit,
      sawCloseSessionAudit](const ua::Structure& request)
    {
      if (const auto* create = dynamic_cast<const ua::CreateSessionRequest*>(&request))
        sawCreateSessionAudit->store(!create->request_header().audit_entry_id().empty());
      if (const auto* activate = dynamic_cast<const ua::ActivateSessionRequest*>(&request))
        sawActivateSessionAudit->store(!activate->request_header().audit_entry_id().empty());
      const auto* write = dynamic_cast<const ua::WriteRequest*>(&request);
      if (write != nullptr && write->request_header().audit_entry_id() == ua::String{"wire-audit-42"})
        sawAuditEntryId->store(true);
      if (const auto* read = dynamic_cast<const ua::ReadRequest*>(&request))
        sawReadWithoutAudit->store(read->request_header().audit_entry_id().empty());
      if (const auto* close = dynamic_cast<const ua::CloseSessionRequest*>(&request))
        sawCloseSessionAudit->store(!close->request_header().audit_entry_id().empty());
    });

  ClientHarness harness(server);
  ua::client::ConnectionConfig config;
  config.endpointUrl = server.endpoint_url_none();
  config.auditEntryIdProvider = []
  {
    return ua::String{"wire-audit-42"};
  };

  auto connectResult = harness.client().try_connect_sync(config);
  ASSERT_TRUE(connectResult.is_good())
    << "connect must reach Active: " << ua::to_string(connectResult.status_code());
  auto connection = std::move(connectResult).value();
  EXPECT_TRUE(sawCreateSessionAudit->load());
  EXPECT_TRUE(sawActivateSessionAudit->load());

  ua::ReadRequest read;
  ua::ReadValueId readTarget;
  readTarget.node_id() = ua::NodeId{static_cast<std::uint32_t>(ua::VariableId::Server_ServerStatus_State)};
  readTarget.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  read.nodes_to_read().push_back(std::move(readTarget));
  EXPECT_TRUE(connection.service_requests().try_read_sync(std::move(read)).is_good());
  EXPECT_TRUE(sawReadWithoutAudit->load())
    << "Read is not in Part 4's client-side auditable Service Set list";

  ua::WriteRequest request;
  ua::WriteValue target;
  target.node_id() = ua::NodeId{static_cast<std::uint32_t>(ua::VariableId::Server_ServerStatus_State)};
  target.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  target.value().value() = ua::Variant{static_cast<std::int32_t>(0)};
  request.nodes_to_write().push_back(std::move(target));
  const auto writeResult = connection.service_requests().try_write_sync(std::move(request));

  EXPECT_TRUE(writeResult.is_good()) << ua::to_string(writeResult.status_code());
  EXPECT_TRUE(sawAuditEntryId->load())
    << "the provider value must be present on the WriteRequest observed at the server wire boundary";
  connection.try_close_sync();
  EXPECT_TRUE(sawCloseSessionAudit->load());
}
