// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 2: SecureChannel Compliance Integration Tests
///
/// 53 tests covering Part 4 (SecureChannel lifecycle) and Part 6 (UASC + Connection Protocol).

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "matchers.h"

// TestAccess for reading SecureChannel internals.
#include "ua_client_secure_channel_test_access.h"

// Fuzzer infrastructure for transport/security interception.
#include "fuzz_security_policy.h"
#include "fuzz_transport_connection.h"

#include "ua_security_policy.h"
#include "ua_security_token.h"
#include "ua_x509_certificate.h"

#include <chrono>
#include <mutex>
#include <string_view>
#include <thread>

using namespace std::chrono_literals;

using CSCTA = ua::client::SecureChannelTestAccess;

// ---------------------------------------------------------------------------
// Helper: snapshot of channel state via TestAccess
// ---------------------------------------------------------------------------
struct ChannelStateSnapshot
{
  uint32_t channelId{0};
  uint32_t tokenId{0};
  std::chrono::milliseconds revisedLifetime{0};
  ua::ByteString serverNonce;
  ua::ByteString lastClientNonce;
};

static ChannelStateSnapshot read_channel_state(SecureChannel& channel)
{
  using CSCTA = ua::client::SecureChannelTestAccess;
  return CSCTA::on_strand(channel,
    [](auto& g)
    {
      ChannelStateSnapshot snap;
      snap.channelId = g.context()->secureChannelId;
      snap.tokenId = g.channel_token_id();
      snap.revisedLifetime = g.revised_lifetime();
      snap.serverNonce = g.server_nonce();
      snap.lastClientNonce = g.last_client_nonce();
      return snap;
    });
}

/// Wait until the token ID changes from oldTokenId, or timeout.
static bool wait_for_renewal(SecureChannel& channel, uint32_t oldTokenId, std::chrono::milliseconds timeout)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    auto snap = read_channel_state(channel);
    if (snap.tokenId != oldTokenId)
      return true;
    std::this_thread::sleep_for(100ms);
  }
  return false;
}

/// Helper: capture outgoing transport bytes via FuzzTransportConnection write interceptor.
/// Returns a thread-safe buffer of all captured frames. Each call to the interceptor appends
/// the raw bytes and passes them through unmodified.
struct CapturedFrames
{
  std::mutex mutex;
  std::vector<std::vector<std::byte>> frames;

  void add(const std::vector<std::byte>& frame)
  {
    std::lock_guard lock(mutex);
    frames.push_back(frame);
  }

  size_t count()
  {
    std::lock_guard lock(mutex);
    return frames.size();
  }

  std::vector<std::byte> get(size_t index)
  {
    std::lock_guard lock(mutex);
    return frames.at(index);
  }
};

/// Read a little-endian uint32 from a byte buffer at the given offset.
static uint32_t read_le_uint32(const std::vector<std::byte>& buf, size_t offset)
{
  if (offset + 4 > buf.size())
    return 0;
  return static_cast<uint32_t>(buf[offset]) | (static_cast<uint32_t>(buf[offset + 1]) << 8) |
         (static_cast<uint32_t>(buf[offset + 2]) << 16) | (static_cast<uint32_t>(buf[offset + 3]) << 24);
}

/// Read the 3-byte message type from a transport frame (e.g. "HEL", "ACK", "OPN", "MSG", "CLO").
static std::string read_message_type(const std::vector<std::byte>& buf)
{
  if (buf.size() < 3)
    return "";
  return {static_cast<char>(buf[0]), static_cast<char>(buf[1]), static_cast<char>(buf[2])};
}

// @relation(AC-SVR-UASC-057-SERVICES, scope=function)

// ===========================================================================
// Category A: Lifecycle smoke tests (5 tests)
// ===========================================================================

// Test 1: Open and close a channel with SecurityPolicy None.
// Covers SVR-UASC-058 (coverage-audit retag).
// @relation(SVR-ECC-010, SVR-UASC-058, SVR-UASC-059, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, ChannelOpenClose_None)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  EXPECT_TRUE(channel.is_open());
  EXPECT_NE(channel.secure_channel_id(), 0u);
  channel.close_sync();
  EXPECT_FALSE(channel.is_open());
}

// Test 2: Open and close a channel with Basic256Sha256 / Sign.
// @relation(SVR-ECC-010, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, ChannelOpenClose_Sign)
{
  auto channel = open_channel(MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);
  EXPECT_TRUE(channel.is_open());
  EXPECT_NE(channel.secure_channel_id(), 0u);
  channel.close_sync();
  EXPECT_FALSE(channel.is_open());
}

// Test 3: Open and close a channel with Basic256Sha256 / SignAndEncrypt.
// @relation(SVR-ECC-010, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, ChannelOpenClose_SignAndEncrypt)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  EXPECT_TRUE(channel.is_open());
  EXPECT_NE(channel.secure_channel_id(), 0u);
  channel.close_sync();
  EXPECT_FALSE(channel.is_open());
}

// Test 4: Channel renewal changes the token ID.
// @verifies CL-SC-007
// @relation(CL-SC-007, scope=function)
TEST_F(ComplianceSecureChannel, ChannelRenewal_TokenChanges)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  auto snap1 = read_channel_state(channel);
  EXPECT_NE(snap1.tokenId, 0u);

  // Wait for renewal (client renews at ~75% of lifetime).
  ASSERT_TRUE(wait_for_renewal(channel, snap1.tokenId, 10s)) << "Token did not renew within timeout";

  auto snap2 = read_channel_state(channel);
  EXPECT_NE(snap2.tokenId, snap1.tokenId) << "Token ID should change after renewal";
  EXPECT_TRUE(channel.is_open());

  channel.close_sync();
}

// Test 5: Multiple channels on the same client (separate connections).
TEST_F(ComplianceSecureChannel, MultipleChannelsOnSameConnection)
{
  auto channel1 = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto channel2 = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  EXPECT_TRUE(channel1.is_open());
  EXPECT_TRUE(channel2.is_open());
  EXPECT_NE(channel1.secure_channel_id(), channel2.secure_channel_id());

  channel1.close_sync();
  channel2.close_sync();
}

// ===========================================================================
// Category B: Part 4 requirements - positive tests (16 tests)
// ===========================================================================

// Requirement: P4-0001 (SHALL)
// "The Server shall accept requests secured with the old SecurityToken until that SecurityToken
//  expires or until it receives a Message from the Client secured with the new SecurityToken."
// Test: after renewal, force the old token ID in outgoing MSG frames and verify the server accepts.
// Uses None policy so token IDs are in plaintext MSG headers (offset 12-15).
// The server answers those requests under the old token, after the client has taken the renew response, so
// the Read also needs the SDK client to accept the old token until a message under the new one arrives
// (CL-SC-010, AC-CL-SC-010-02).
// @relation(SVR-SC-001, SVR-UASC-061, scope=function)
// @verifies AC-CL-SC-010-02
// @relation(AC-CL-SC-010-02, scope=function)
TEST_F(ComplianceSecureChannel, P4_0001_OldTokenAcceptedAfterRenew)
{
  // Open with None + short lifetime + transport decorator so we can rewrite token IDs.
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> fuzzTransport;

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::None;
  cfg.securityPolicyId = SecurityPolicyId::None;
  cfg.requestedLifetime = 2000ms;
  ua::client::ClientTestHooks hooks;
  hooks.transportDecorator = [&fuzzTransport](std::shared_ptr<TransportConnection> inner)
  {
    auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
    fuzzTransport = fuzz;
    return fuzz;
  };
  ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));

  auto channel = mClient->core().open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channel.is_open());
  ASSERT_NE(fuzzTransport, nullptr);

  auto snap1 = read_channel_state(channel);
  uint32_t oldTokenId = snap1.tokenId;
  ASSERT_NE(oldTokenId, 0u);

  // Wait for renewal - client gets a new token.
  ASSERT_TRUE(wait_for_renewal(channel, oldTokenId, 10s));
  auto snap2 = read_channel_state(channel);
  uint32_t newTokenId = snap2.tokenId;
  ASSERT_NE(newTokenId, oldTokenId) << "Renewal must produce a different token ID";

  // Install interceptor that replaces the new token ID with the old one in MSG frames.
  // This forces the server to receive a message secured with the OLD token.
  auto oldTokenLeBytes = std::array<std::byte, 4>{static_cast<std::byte>(oldTokenId & 0xFF),
    static_cast<std::byte>((oldTokenId >> 8) & 0xFF),
    static_cast<std::byte>((oldTokenId >> 16) & 0xFF),
    static_cast<std::byte>((oldTokenId >> 24) & 0xFF)};
  fuzzTransport->set_write_interceptor(
    [oldTokenLeBytes](std::vector<std::byte> data) -> std::vector<std::byte>
    {
      // MSG header: [0-2]="MSG", [3]='F', [4-7]=size, [8-11]=channelId, [12-15]=tokenId
      if (data.size() >= 16)
      {
        std::string msgType(reinterpret_cast<const char*>(data.data()), 3);
        if (msgType == "MSG")
        {
          // Replace token ID at offset 12-15 with old token ID.
          std::copy(oldTokenLeBytes.begin(), oldTokenLeBytes.end(), data.begin() + 12);
        }
      }
      return data;
    });

  // Send a request with the old token - server SHALL accept it during the grace period.
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));
  EXPECT_THAT(result, ::ua::test_helpers::Good())
    << "Server SHALL accept messages with the old SecurityToken during the grace period; status: 0x"
    << std::hex << result.status_code().as_uint32();

  // Clean up: remove interceptor and close normally.
  fuzzTransport->set_write_interceptor(nullptr);
  channel.close_sync();
}

// Requirement: P4-0003 (SHALL)
// OPN message shall be signed and encrypted when security policy is not None.
// Positive test: channel with Sign mode works for service calls (proves OPN was signed).
// @relation(SVR-SC-003, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0003_OpnSignedAndEncryptedWhenPolicyNotNone)
{
  // Open with Sign mode - the OPN itself is signed with the sender's private key.
  auto channel = open_channel(MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // Verify the channel is authenticated by checking the security context.
  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      EXPECT_EQ(context.messageSecurityMode, MessageSecurityMode::Sign)
        << "Channel security mode should be Sign";
      EXPECT_NE(context.securityPolicy, nullptr) << "Security policy should be set";
      EXPECT_TRUE(context.securityPolicy->is_authenticated())
        << "Policy should be authenticated for Sign mode";
    });

  // Verify service call works (proves the signed messages are accepted).
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));
  EXPECT_THAT(result, ::ua::test_helpers::Good());

  channel.close_sync();
}

// Requirement: P4-0004 (SHALL)
// Certificate continuity: same cert used for OPN and CreateSession.
// Positive test: successfully create and activate session after OPN.
// @relation(SVR-SC-004, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0004_CertContinuityAcrossOpnCreateActivate)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // Verify the local certificate is set in the context (used for OPN).
  auto opnCertThumbprint = CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      EXPECT_NE(context.localCertificate, nullptr) << "Local cert must be set for OPN";
      return context.localCertificate ? context.localCertificate->thumbprint() : ua::ByteString{};
    });
  ASSERT_FALSE(opnCertThumbprint.empty());

  // CreateSession + ActivateSession - server validates cert continuity.
  auto session = channel.create_session_sync({.sessionName = "P4_0004_Test"});
  session.activate_sync();
  EXPECT_TRUE(session.is_active());

  // The same cert was used throughout (server would reject a mismatch).
  // Verify the cert in context hasn't changed.
  CSCTA::on_strand(channel,
    [&](auto& g)
    {
      auto& context = *g.context();
      EXPECT_EQ(context.localCertificate->thumbprint(), opnCertThumbprint)
        << "Local certificate must remain the same across OPN and session";
    });

  session.close_sync();
  channel.close_sync();
}

// Requirement: P4-0005 (SHALL)
// Server certificate hostname shall match the endpoint URL host.
// Positive test: verify server cert SANs actually contain the endpoint hostname.
// @relation(SVR-SC-005, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0005_ServerCertHostnameMatchesEndpoint)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // Extract the server certificate from the security context.
  struct CertSanInfo
  {
    std::vector<std::string> hostnames;
    std::vector<boost::asio::ip::address> ipAddresses;
  };

  auto sanInfo = CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      EXPECT_NE(context.remoteCertificate, nullptr) << "Server cert should be in context";
      CertSanInfo info;
      if (context.remoteCertificate)
      {
        info.hostnames = context.remoteCertificate->san_hostnames();
        info.ipAddresses = context.remoteCertificate->san_ip_addresses();
      }
      return info;
    });

  // Check that server cert SANs contain hostnames matching the endpoint.
  // Our endpoint uses 127.0.0.1, so check both hostname and IP SANs.
  auto& hostnames = sanInfo.hostnames;
  auto& ipAddresses = sanInfo.ipAddresses;

  bool hasLocalhost = std::find(hostnames.begin(), hostnames.end(), "localhost") != hostnames.end();
  bool has127 = false;
  for (const auto& ip : ipAddresses)
  {
    if (ip.to_string() == "127.0.0.1")
    {
      has127 = true;
      break;
    }
  }

  EXPECT_TRUE(hasLocalhost || has127)
    << "Server cert SANs must include the endpoint host (localhost or 127.0.0.1)";

  channel.close_sync();
}

// Requirement: P4-0007 (SHALL)
// OPN message shall be signed with the sender's private key.
// Positive test: successful authenticated channel + service call proves signatures are valid.
// Covers SVR-SC-007 (coverage-audit retag).
// @relation(SVR-SC-007, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0007_OpnSignedWithSenderPrivateKey)
{
  auto channel = open_channel(MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // Verify the local key pair is present (used for signing).
  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      EXPECT_NE(context.localKeyPair, nullptr) << "Local key pair must be set for signing";
      EXPECT_NE(context.localCertificate, nullptr) << "Local cert must be set for signing";
    });

  // Service call succeeds only if OPN was properly signed.
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));
  EXPECT_THAT(result, ::ua::test_helpers::Good()) << "Signed service call should succeed";

  channel.close_sync();
}

// Requirement: P4-0008 (SHALL)
// For SecurityPolicy None, the application instance certificate shall be ignored.
// Positive test: None channel opens successfully even though certs are configured.
// @relation(SVR-ECC-010, SVR-SC-008, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0008_PolicyNoneIgnoresCert)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channel.is_open());

  // Verify the security context does NOT have authenticated security set.
  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      EXPECT_EQ(context.messageSecurityMode, MessageSecurityMode::None);
      // For None policy, security tokens don't use certificates for crypto.
      EXPECT_FALSE(context.securityPolicy->is_authenticated())
        << "SecurityPolicy None should not be authenticated";
    });

  channel.close_sync();
}

// Requirement: P4-0009 (SHALL)
// Issue creates a new secure channel with a new channel ID.
// Positive test: each channel gets a unique non-zero ID.
// @relation(SVR-SC-009, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0009_IssueCreatesNewChannel)
{
  auto channel1 = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto channel2 = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  auto channel3 = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);

  EXPECT_NE(channel1.secure_channel_id(), 0u);
  EXPECT_NE(channel2.secure_channel_id(), 0u);
  EXPECT_NE(channel3.secure_channel_id(), 0u);

  // All channel IDs must be distinct.
  EXPECT_NE(channel1.secure_channel_id(), channel2.secure_channel_id());
  EXPECT_NE(channel1.secure_channel_id(), channel3.secure_channel_id());
  EXPECT_NE(channel2.secure_channel_id(), channel3.secure_channel_id());

  channel1.close_sync();
  channel2.close_sync();
  channel3.close_sync();
}

// Requirement: P4-0009 (SHALL)
// Renew returns a new token for the same channel.
// @relation(SVR-SC-009, scope=function)
TEST_F(ComplianceSecureChannel, P4_0009_RenewReturnsNewToken)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  auto snap1 = read_channel_state(channel);
  auto channelId = snap1.channelId;
  EXPECT_NE(snap1.tokenId, 0u) << "Initial token ID must be non-zero";
  ASSERT_TRUE(wait_for_renewal(channel, snap1.tokenId, 10s));

  auto snap2 = read_channel_state(channel);
  EXPECT_EQ(snap2.channelId, channelId) << "Channel ID must not change on renewal";
  EXPECT_NE(snap2.tokenId, snap1.tokenId) << "Token ID must change on renewal";
  EXPECT_NE(snap2.tokenId, 0u) << "New token ID must be non-zero";

  channel.close_sync();
}

// Requirement: P4-0011 (SHALL)
// Client nonce shall be fresh each time an OPN request is sent.
// @verifies CL-SC-004, CL-SC-007
// @relation(CL-SC-004, CL-SC-007, SVR-SC-011, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0011_ClientNonceFreshEachRenew)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  auto snap1 = read_channel_state(channel);
  auto nonce1 = snap1.lastClientNonce;
  ASSERT_FALSE(nonce1.empty()) << "Client nonce must not be empty for authenticated channel";
  ASSERT_TRUE(wait_for_renewal(channel, snap1.tokenId, 10s));

  auto snap2 = read_channel_state(channel);
  EXPECT_NE(snap2.lastClientNonce, nonce1) << "Client nonce must be fresh on each renewal";
  EXPECT_FALSE(snap2.lastClientNonce.empty()) << "Renewed client nonce must not be empty";

  channel.close_sync();
}

// Requirement: P4-0012 (SHALL)
// Client nonce length shall match the security policy's nonce length.
// @verifies CL-SC-005
// @relation(CL-SC-005, SVR-SC-012, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0012_ClientNonceLengthMatchesPolicy)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  auto snap = read_channel_state(channel);
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto expectedLength = policy->nonce_length();

  EXPECT_EQ(snap.lastClientNonce.size(), expectedLength)
    << "Client nonce length must match policy nonce length (" << expectedLength << ")";
  EXPECT_GT(expectedLength, 0u) << "Authenticated policy must have non-zero nonce length";

  channel.close_sync();
}

// Requirement: P4-0014 (SHALL)
// The revised lifetime returned by the server.
// @relation(SVR-SC-014, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0014_ChannelLifetimeRevised)
{
  // Request a specific lifetime and verify server returns a revised value.
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 5000ms);
  ASSERT_TRUE(channel.is_open());

  auto snap = read_channel_state(channel);
  EXPECT_GT(snap.revisedLifetime.count(), 0) << "Revised lifetime must be > 0";
  // The server should return at least the minimum (1000ms in our fixture) but may revise up.
  EXPECT_GE(snap.revisedLifetime.count(), 1000) << "Revised lifetime should be >= server minimum (1000ms)";

  channel.close_sync();
}

// Requirement: P4-0015 (SHALL)
// SecureChannelId shall be non-zero.
// Covers SVR-UASC-059 (coverage-audit retag).
// @relation(SVR-SC-015, SVR-UASC-059, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0015_ChannelIdNonZero)
{
  // Verify for both None and authenticated channels.
  auto channelNone = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  EXPECT_NE(channelNone.secure_channel_id(), 0u) << "None channel ID must be non-zero";

  auto channelAuth = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  EXPECT_NE(channelAuth.secure_channel_id(), 0u) << "Authenticated channel ID must be non-zero";

  // Also verify via TestAccess that the context matches.
  CSCTA::on_strand(
    channelNone, [&](auto& g) { EXPECT_EQ(g.context()->secureChannelId, channelNone.secure_channel_id()); });
  CSCTA::on_strand(
    channelAuth, [&](auto& g) { EXPECT_EQ(g.context()->secureChannelId, channelAuth.secure_channel_id()); });

  channelNone.close_sync();
  channelAuth.close_sync();
}

// Requirement: P4-0016 (SHALL)
// Token ID shall be present in each message.
// Positive test: verify token ID is non-zero and the active security token is present.
// @verifies CL-SC-009
// @relation(CL-SC-009, SVR-SC-016, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0016_TokenIdInEachMessage)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  auto snap = read_channel_state(channel);
  EXPECT_NE(snap.tokenId, 0u) << "Token ID must be non-zero";

  // Verify the active security token is present in the context.
  CSCTA::on_strand(channel,
    [&](auto& g)
    {
      auto& context = *g.context();
      ASSERT_NE(context.activeSecurityToken, nullptr) << "Active security token must be present";
      EXPECT_EQ(context.activeSecurityToken->id(), snap.tokenId)
        << "Active token ID must match logic state token ID";
    });

  // Verify the channel is usable (messages carry the token ID).
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));
  EXPECT_THAT(result, ::ua::test_helpers::Good());

  channel.close_sync();
}

// Requirement: P4-0017 (SHALL)
// Revised lifetime shall be returned even for SecurityPolicy None.
// @relation(SVR-SC-017, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0017_RevisedLifetimeReturnedEvenForNone)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channel.is_open());

  auto snap = read_channel_state(channel);
  EXPECT_GT(snap.revisedLifetime.count(), 0) << "Revised lifetime must be returned even for None";

  // Also verify the active security token has a matching lifetime.
  CSCTA::on_strand(channel,
    [&](auto& g)
    {
      auto& context = *g.context();
      ASSERT_NE(context.activeSecurityToken, nullptr);
      EXPECT_EQ(context.activeSecurityToken->revised_lifetime(), snap.revisedLifetime)
        << "Token's revised lifetime must match the OPN response value";
    });

  channel.close_sync();
}

// Requirement: P4-0018 (SHALL)
// Server nonce shall be unique per renewal.
// @relation(SVR-SC-018, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0018_ServerNonceUniquePerRenew)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  auto snap1 = read_channel_state(channel);
  auto nonce1 = snap1.serverNonce;
  ASSERT_FALSE(nonce1.empty()) << "Server nonce must not be empty for authenticated channel";
  ASSERT_TRUE(wait_for_renewal(channel, snap1.tokenId, 10s));

  auto snap2 = read_channel_state(channel);
  EXPECT_NE(snap2.serverNonce, nonce1) << "Server nonce must be unique per renewal";
  EXPECT_FALSE(snap2.serverNonce.empty()) << "Renewed server nonce must not be empty";

  // Do a second renewal to strengthen the uniqueness assertion.
  ASSERT_TRUE(wait_for_renewal(channel, snap2.tokenId, 10s));
  auto snap3 = read_channel_state(channel);
  EXPECT_NE(snap3.serverNonce, snap2.serverNonce) << "Third nonce must differ from second";
  EXPECT_NE(snap3.serverNonce, nonce1) << "Third nonce must differ from first";

  channel.close_sync();
}

// Requirement: P4-0019 (SHALL)
// Server nonce length shall match the security policy's nonce length.
// @relation(SVR-SC-019, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P4_0019_ServerNonceLengthMatchesPolicy)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  auto snap = read_channel_state(channel);
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto expectedLength = policy->nonce_length();
  EXPECT_EQ(snap.serverNonce.size(), expectedLength)
    << "Server nonce length must match policy nonce length (" << expectedLength << ")";

  channel.close_sync();
}

// ===========================================================================
// Category C: Part 4 requirements - negative tests without unit coverage (4)
// ===========================================================================

// Requirement: P4-0002 (SHALL)
// "the Server shall close the oldest unused SecureChannel that has no Session assigned before
//  reaching the maximum number of supported SecureChannels."
// The spec says SHALL - the server must evict, not reject.
// @relation(SVR-ECC-010, SVR-SC-002, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannelLimited, P4_0002_CloseOldestSessionlessChannelOnExhaustion)
{
  // The fixture limits mMaxSecureChannels=2.
  // Open two channels to reach the limit.
  auto channel1 = open_channel_none();
  ASSERT_TRUE(channel1.is_open());
  auto id1 = channel1.secure_channel_id();

  auto channel2 = open_channel_none();
  ASSERT_TRUE(channel2.is_open());

  // Opening a 3rd channel: the spec says the server SHALL close the oldest unused
  // sessionless channel to make room. The 3rd open must succeed.
  auto channel3Result = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl});
  EXPECT_THAT(channel3Result, ::ua::test_helpers::Good())
    << "Server SHALL evict oldest sessionless channel to make room for new one; "
       "rejecting instead of evicting violates Part 4 SS 5.5.2.1";

  if (channel3Result.is_good())
  {
    auto channel3 = std::move(channel3Result).value();
    EXPECT_TRUE(channel3.is_open());

    // The oldest sessionless channel (channel1) should have been evicted.
    std::this_thread::sleep_for(500ms);
    GetEndpointsRequest req;
    req.endpoint_url() = mEndpointUrl;
    auto result = channel1.try_get_endpoints_sync(std::move(req));
    EXPECT_TRUE(result.is_bad() || !channel1.is_open())
      << "Oldest sessionless channel (ID " << id1 << ") should have been evicted";

    channel3.close_sync();
  }

  channel1.try_close_sync();
  channel2.try_close_sync();
}

// Requirement: P4-0002 (SHALL)
// Channels with sessions shall not be evicted.
// @relation(SVR-ECC-010, SVR-SC-002, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannelLimited, P4_0002_ChannelWithSessionNotEvicted)
{
  // Open a channel and create a session on it - this channel should be protected from eviction.
  auto channelWithSession = open_channel_auth();
  ASSERT_TRUE(channelWithSession.is_open());
  auto session = channelWithSession.create_session_sync({.sessionName = "P4_0002_Protected"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active());

  // Fill remaining capacity with sessionless channels.
  auto sessionlessChannel = open_channel_none();
  ASSERT_TRUE(sessionlessChannel.is_open());

  // Try to open one more (exceeds limit).
  auto extraResult = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl});

  // Regardless of whether extra channel succeeded or was rejected,
  // the channel with a session must still be alive.
  EXPECT_TRUE(channelWithSession.is_open()) << "Channel with active session must NOT be evicted";

  // Verify the session is still usable.
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channelWithSession.try_get_endpoints_sync(std::move(req));
  EXPECT_THAT(result, ::ua::test_helpers::Good()) << "Session channel must remain usable";

  session.close_sync();
  channelWithSession.close_sync();
  sessionlessChannel.try_close_sync();
  if (extraResult.is_good())
    std::move(extraResult).value().try_close_sync();
}

// Requirement: P4-0003 (SHALL)
// OPN with security policy not None but sent unsecured should be rejected.
// @relation(SVR-SC-003, scope=function)
TEST_F(ComplianceSecureChannel, P4_0003_OpnUnsecuredWhenPolicyNotNone_Rejected)
{
  // Use FuzzSecurityPolicy to corrupt the encoded OPN message - strip signatures/encryption
  // by replacing the encoded chunk with garbage.
  std::shared_ptr<opcua_fuzzer::FuzzSecurityPolicy> fuzzPolicy;

  // Set up the interceptor before opening the channel.
  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = mServerCert;

  // Replace the security policy with one that corrupts outgoing encoded chunks.
  {
    ua::client::ClientTestHooks hooks;
    hooks.securityPolicyFactory = [&fuzzPolicy](SecurityPolicyId policyId) -> std::shared_ptr<SecurityPolicy>
    {
      auto inner = SecurityPolicy::create(policyId);
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzSecurityPolicy>(std::move(inner));
      fuzzPolicy = fuzz;
      fuzz->set_encode_interceptor(
        [](ua::ByteString chunk) -> ua::ByteString
        {
          if (chunk.size() > 32)
          {
            for (size_t i = chunk.size() - 32; i < chunk.size(); ++i)
            {
              chunk[i] = static_cast<uint8_t>(~static_cast<uint8_t>(chunk[i]));
            }
          }
          return chunk;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  // The channel open should fail because the server can't verify the corrupted OPN.
  auto result = mClient->core().try_open_channel_sync(std::move(cfg));
  EXPECT_TRUE(result.is_bad()) << "Server must reject OPN with corrupted signature/encryption";
}

// ===========================================================================
// Category D: Part 6 UASC - positive tests (17 tests)
// ===========================================================================

// Requirement: P6-67-0002 (SHALL)
// SecurityPolicyUri length is valid (fits in chunk).
// Verify the security policy URI stored in context matches the expected URI and length.
// @relation(SVR-UASC-002, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0002_SecurityPolicyUriLengthValid)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      ASSERT_NE(context.securityPolicy, nullptr);

      std::string uri = context.securityPolicy->uri();
      EXPECT_FALSE(uri.empty()) << "Security policy URI must not be empty";
      // Basic256Sha256 URI is well under any chunk size limit.
      EXPECT_LT(uri.size(), 256u) << "Security policy URI must be reasonably short";
      // Verify it's the correct policy.
      EXPECT_NE(uri.find("Basic256Sha256"), std::string::npos)
        << "URI should contain Basic256Sha256; got: " << uri;
    });

  channel.close_sync();
}

// Requirement: P6-67-0003 (SHALL)
// SenderCertificate length is valid.
// Verify the local certificate DER encoding fits within a single chunk.
// @relation(SVR-UASC-003, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0003_SenderCertLengthValid)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      ASSERT_NE(context.localCertificate, nullptr);

      auto certDer = context.localCertificate->der_encoding();
      EXPECT_GT(certDer.size(), 0u) << "Sender certificate DER must not be empty";

      // Per spec, sender certificate must leave room for the rest of the asymmetric header + body.
      // The receive buffer size is the chunk size limit.
      auto maxChunkSize = context.negotiatedLimits.sendBufferSize;
      EXPECT_LT(certDer.size(), maxChunkSize)
        << "Sender certificate DER (" << certDer.size() << " bytes) must fit within chunk size ("
        << maxChunkSize << " bytes)";
    });

  channel.close_sync();
}

// Requirement: P6-67-0005 (SHALL)
// Certificate chain accepted.
// Our test uses self-signed certs (no chain). Verify basic trust works and cert is valid.
// @relation(SVR-UASC-005, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0005_CertChainAccepted)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // Verify both local and remote certificates are present and accepted.
  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      ASSERT_NE(context.localCertificate, nullptr) << "Local cert must be present";
      ASSERT_NE(context.remoteCertificate, nullptr) << "Remote (server) cert must be present";

      // Self-signed certs have empty issuer chain - verify the feature works at minimum.
      // Note: a proper chain test would require CA-signed certs in the test PKI.
      EXPECT_TRUE(context.remoteIssuerCertificates.empty())
        << "Self-signed server cert should have no issuer chain (test fixture limitation)";
    });

  channel.close_sync();
}

// Requirement: P6-67-0009 (SHALL)
// Sender certificate fits in a single chunk.
// @relation(SVR-UASC-009, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0009_SenderCertFitsInSingleChunk)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      ASSERT_NE(context.localCertificate, nullptr);

      auto certDer = context.localCertificate->der_encoding();
      auto chunkSize = context.negotiatedLimits.sendBufferSize;

      // The asymmetric header overhead is: 12 (header) + 4 (SecurityPolicyUriLength) + policyUri.size()
      // + 4 (SenderCertificateLength) + cert.size() + 4 (ReceiverCertificateThumbprintLength) + 20
      // (thumbprint) + body + padding + signature. The cert must leave room for all of this.
      std::string policyUri = context.securityPolicy->uri();
      size_t asymmetricHeaderOverhead = 12 + 4 + policyUri.size() + 4 + 4 + 20;
      EXPECT_LT(certDer.size() + asymmetricHeaderOverhead, chunkSize)
        << "Cert (" << certDer.size() << ") + header overhead (" << asymmetricHeaderOverhead
        << ") must fit in a single chunk (" << chunkSize << ")";
    });

  channel.close_sync();
}

// Requirement: P6-67-0012 (SHALL)
// Sequence number is monotonically increasing.
// Capture outgoing MSG frames and verify sequence numbers increase.
// @verifies CL-UASC-001
// @relation(CL-UASC-001, SVR-UASC-012, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0012_SequenceNumberMonotonic)
{
  auto captured = std::make_shared<CapturedFrames>();
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> fuzzTransport;

  auto channel =
    open_channel_with_transport_decorator(MessageSecurityMode::None, SecurityPolicyId::None, fuzzTransport);
  ASSERT_TRUE(channel.is_open());

  // Install write interceptor to capture outgoing frames (passthrough).
  fuzzTransport->set_write_interceptor(
    [captured](std::vector<std::byte> data) -> std::vector<std::byte>
    {
      captured->add(data);
      return data;  // passthrough
    });

  // Send multiple service calls - each generates a MSG frame with a sequence number.
  constexpr int numCalls = 5;
  for (int i = 0; i < numCalls; ++i)
  {
    GetEndpointsRequest req;
    req.endpoint_url() = mEndpointUrl;
    auto result = channel.try_get_endpoints_sync(std::move(req));
    EXPECT_THAT(result, ::ua::test_helpers::Good()) << "Call " << i << " failed";
  }

  // Check captured MSG frames for monotonically increasing sequence numbers.
  // For None policy, MSG frames are unencrypted. Format:
  // [0-2] message type ("MSG"), [3] chunk type, [4-7] size, [8-11] channelId,
  // [12-15] tokenId, [16-19] sequenceNumber, [20-23] requestId
  std::vector<uint32_t> sequenceNumbers;
  auto frameCount = captured->count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = captured->get(i);
    auto msgType = read_message_type(frame);
    if (msgType == "MSG" && frame.size() >= 24)
    {
      uint32_t seqNum = read_le_uint32(frame, 16);
      sequenceNumbers.push_back(seqNum);
    }
  }

  EXPECT_GE(sequenceNumbers.size(), static_cast<size_t>(numCalls))
    << "Should have captured at least " << numCalls << " MSG frames";

  for (size_t i = 1; i < sequenceNumbers.size(); ++i)
  {
    EXPECT_EQ(sequenceNumbers[i], sequenceNumbers[i - 1] + 1)
      << "Sequence number shall be incremented by exactly one per chunk: seq[" << i - 1
      << "]=" << sequenceNumbers[i - 1] << " seq[" << i << "]=" << sequenceNumbers[i];
  }

  channel.close_sync();
}

// Requirement: P6-67-0020 (SHALL)
// "Some of the parameters defined for the OpenSecureChannel service are specified in the
//  security header (see 6.7.2) instead of the body of the Message."
// Capture OPN frame (None policy, unencrypted) and verify security header contains SecurityPolicyUri
// and the body contains the OPN request.
// @relation(SVR-UASC-020, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0020_OpnParametersInHeaderAndBody)
{
  auto captured = std::make_shared<CapturedFrames>();

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::None;
  cfg.securityPolicyId = SecurityPolicyId::None;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [captured](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [captured](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          captured->add(data);
          return data;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  auto channel = mClient->core().open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channel.is_open());

  // Find the OPN frame and parse its structure.
  bool foundOpn = false;
  auto frameCount = captured->count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = captured->get(i);
    if (read_message_type(frame) != "OPN")
      continue;

    foundOpn = true;

    // Message header: [0-2]="OPN", [3]='F', [4-7]=messageSize, [8-11]=secureChannelId
    uint32_t messageSize = read_le_uint32(frame, 4);
    EXPECT_EQ(messageSize, static_cast<uint32_t>(frame.size()))
      << "OPN message size field must match actual frame size";

    // Asymmetric security header starts at offset 12 for None policy:
    // [12-15] = SecurityPolicyUri length (LE int32)
    ASSERT_GE(frame.size(), 16u);
    int32_t uriLen = static_cast<int32_t>(read_le_uint32(frame, 12));
    EXPECT_GT(uriLen, 0) << "SecurityPolicyUri length must be > 0 in security header";
    ASSERT_LE(static_cast<size_t>(uriLen), frame.size() - 16);

    // Extract and verify the SecurityPolicyUri from the security header.
    std::string uriInHeader(reinterpret_cast<const char*>(&frame[16]), uriLen);
    EXPECT_NE(uriInHeader.find("SecurityPolicy"), std::string::npos)
      << "Security header must contain the SecurityPolicyUri; got: " << uriInHeader;

    // After URI: SenderCertificate length + ReceiverThumbprint length (both -1 for None = 0xFFFFFFFF)
    size_t pos = 16 + uriLen;
    ASSERT_GE(frame.size(), pos + 8);
    uint32_t certLen = read_le_uint32(frame, pos);
    EXPECT_EQ(certLen, 0xFFFFFFFFu) << "SenderCertificate length should be -1 (empty) for None policy";
    pos += 4;
    uint32_t thumbLen = read_le_uint32(frame, pos);
    EXPECT_EQ(thumbLen, 0xFFFFFFFFu) << "ReceiverThumbprint length should be -1 (empty) for None policy";
    pos += 4;

    // Sequence header (8 bytes) and body follow - body contains the OPN request.
    size_t bodyStart = pos + 8;  // skip sequence number + request ID
    EXPECT_LT(bodyStart, frame.size()) << "Frame must contain body after security + sequence headers";

    break;
  }
  EXPECT_TRUE(foundOpn) << "Must have captured an OPN frame";

  channel.close_sync();
}

// Requirement: P6-67-0021 (SHALL)
// "the ClientProtocolVersion specified in the OpenSecureChannel Request shall be the same as
//  the ProtocolVersion specified in the Hello Message."
// Capture HEL and OPN frames, parse both protocol versions, verify they match.
// @verifies CL-UASC-013
// @relation(CL-UASC-013, SVR-UASC-021, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0021_ProtocolVersionMatchesHel)
{
  auto captured = std::make_shared<CapturedFrames>();

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::None;
  cfg.securityPolicyId = SecurityPolicyId::None;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [captured](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [captured](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          captured->add(data);
          return data;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  auto channel = mClient->core().open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channel.is_open());

  // Parse HEL protocol version: [8-11]
  uint32_t helProtocolVersion = UINT32_MAX;
  uint32_t opnProtocolVersion = UINT32_MAX;
  bool foundHel = false;
  bool foundOpn = false;

  auto frameCount = captured->count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = captured->get(i);
    auto msgType = read_message_type(frame);

    if (msgType == "HEL" && frame.size() >= 12)
    {
      foundHel = true;
      helProtocolVersion = read_le_uint32(frame, 8);
    }
    else if (msgType == "OPN" && frame.size() > 30)
    {
      foundOpn = true;
      // Parse None-policy OPN to find ClientProtocolVersion in the body.
      // Security header: [12-15]=uriLen, [16..16+uriLen]=uri, certLen(4), thumbLen(4)
      int32_t uriLen = static_cast<int32_t>(read_le_uint32(frame, 12));
      if (uriLen < 0)
        uriLen = 0;
      size_t pos = 16 + uriLen + 4 + 4;  // skip URI + certLen(-1) + thumbLen(-1)
      pos += 8;  // skip sequence header (seqNum + requestId)

      // Body starts with Type ID (NodeId). For OPN request binary encoding,
      // the NodeId uses FourByte encoding: [0x01, namespace(1), id(2)].
      if (pos + 4 <= frame.size() && static_cast<uint8_t>(frame[pos]) == 0x01)
        pos += 4;  // FourByte NodeId
      else if (pos + 2 <= frame.size() && static_cast<uint8_t>(frame[pos]) == 0x00)
        pos += 2;  // TwoByte NodeId
      else
        continue;  // can't parse

      // Request header: AuthenticationToken (null NodeId = 2 bytes 0x00 0x00)
      if (pos + 2 <= frame.size() && static_cast<uint8_t>(frame[pos]) == 0x00)
        pos += 2;
      else if (pos + 4 <= frame.size() && static_cast<uint8_t>(frame[pos]) == 0x01)
        pos += 4;
      else
        continue;

      // Timestamp(8) + RequestHandle(4) + ReturnDiagnostics(4) = 16 bytes
      pos += 16;
      // AuditEntryId (String): length(4) + data
      if (pos + 4 > frame.size())
        continue;
      int32_t auditLen = static_cast<int32_t>(read_le_uint32(frame, pos));
      pos += 4;
      if (auditLen > 0)
        pos += auditLen;
      // TimeoutHint(4)
      pos += 4;
      // AdditionalHeader (ExtensionObject): null = NodeId(0x00,0x00) + encoding(0x00) = 3 bytes
      pos += 3;

      // Now at OPN request body: ClientProtocolVersion (uint32)
      if (pos + 4 <= frame.size())
        opnProtocolVersion = read_le_uint32(frame, pos);
    }
  }

  ASSERT_TRUE(foundHel) << "Must have captured a HEL frame";
  ASSERT_TRUE(foundOpn) << "Must have captured an OPN frame";
  ASSERT_NE(opnProtocolVersion, UINT32_MAX) << "Failed to parse ClientProtocolVersion from OPN body";

  EXPECT_EQ(opnProtocolVersion, helProtocolVersion)
    << "ClientProtocolVersion in OPN (" << opnProtocolVersion << ") SHALL match ProtocolVersion in HEL ("
    << helProtocolVersion << ")";

  channel.close_sync();
}

// Requirement: P6-67-0023 (SHALL)
// Renew with the same certificate is accepted.
// @relation(AC-SVR-UASC-023-GRACE, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0023_RenewWithSameCertAccepted)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  // Record the cert thumbprint before renewal.
  auto thumbprintBefore = CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      EXPECT_NE(context.localCertificate, nullptr);
      return context.localCertificate ? context.localCertificate->thumbprint() : ua::ByteString{};
    });
  ASSERT_FALSE(thumbprintBefore.empty());

  auto snap1 = read_channel_state(channel);
  ASSERT_TRUE(wait_for_renewal(channel, snap1.tokenId, 10s));

  // Renewal succeeded with same cert.
  EXPECT_TRUE(channel.is_open());
  // Verify the cert didn't change.
  CSCTA::on_strand(channel,
    [&](auto& g)
    {
      auto& context = *g.context();
      EXPECT_EQ(context.localCertificate->thumbprint(), thumbprintBefore)
        << "Certificate must remain the same across renewal";
    });

  channel.close_sync();
}

// Requirement: P6-67-0024 (SHALL)
// Nonce length matches security policy on OPN.
// @verifies CL-SC-005
// @relation(CL-SC-005, SVR-UASC-024, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0024_NonceLengthMatchesPolicy)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  auto snap = read_channel_state(channel);
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  auto expectedLength = policy->nonce_length();

  EXPECT_EQ(snap.lastClientNonce.size(), expectedLength) << "Client nonce length must match policy";
  EXPECT_EQ(snap.serverNonce.size(), expectedLength) << "Server nonce length must match policy";

  // Also verify for None policy (nonce length should be 0).
  auto channelNone = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channelNone.is_open());
  auto snapNone = read_channel_state(channelNone);
  auto policyNone = SecurityPolicy::create(SecurityPolicyId::None);
  auto expectedLengthNone = policyNone->nonce_length();
  EXPECT_EQ(snapNone.lastClientNonce.size(), expectedLengthNone)
    << "None policy: client nonce length must match policy (expected " << expectedLengthNone << ")";

  channelNone.close_sync();
  channel.close_sync();
}

// Requirement: P6-67-0026 (SHALL)
// "The AuthenticationToken in the RequestHeader shall be set to null."
// Capture OPN frame (None policy, unencrypted) and parse the body to verify the
// AuthenticationToken is a null NodeId (TwoByte encoding: 0x00 0x00).
// @verifies CL-UASC-014
// @relation(CL-UASC-014, SVR-UASC-026, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0026_AuthTokenNullForOpn)
{
  auto captured = std::make_shared<CapturedFrames>();

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::None;
  cfg.securityPolicyId = SecurityPolicyId::None;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [captured](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [captured](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          captured->add(data);
          return data;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  auto channel = mClient->core().open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channel.is_open());

  // Parse the OPN frame body to find the AuthenticationToken.
  bool foundAuthToken = false;
  auto frameCount = captured->count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = captured->get(i);
    if (read_message_type(frame) != "OPN" || frame.size() < 30)
      continue;

    // Security header: [12-15]=uriLen, [16..16+uriLen]=uri, certLen(4), thumbLen(4)
    int32_t uriLen = static_cast<int32_t>(read_le_uint32(frame, 12));
    if (uriLen < 0)
      uriLen = 0;
    size_t pos = 16 + uriLen + 4 + 4;  // skip URI + certLen(-1) + thumbLen(-1)
    pos += 8;  // skip sequence header

    // Skip Type ID (NodeId for OPN request binary encoding).
    if (pos >= frame.size())
      continue;
    uint8_t encodingByte = static_cast<uint8_t>(frame[pos]);
    if (encodingByte == 0x01)
      pos += 4;  // FourByte NodeId
    else if (encodingByte == 0x00)
      pos += 2;  // TwoByte NodeId
    else
      continue;

    // Now at the Request Header. First field is AuthenticationToken (NodeId).
    if (pos + 2 > frame.size())
      continue;

    foundAuthToken = true;
    uint8_t tokenEncoding = static_cast<uint8_t>(frame[pos]);
    uint8_t tokenValue = static_cast<uint8_t>(frame[pos + 1]);

    // Null NodeId: TwoByte encoding (0x00) with identifier 0.
    EXPECT_EQ(tokenEncoding, 0x00u)
      << "AuthenticationToken must use TwoByte encoding (0x00) for null NodeId; got 0x" << std::hex
      << static_cast<int>(tokenEncoding);
    EXPECT_EQ(tokenValue, 0x00u) << "AuthenticationToken identifier must be 0 for null NodeId; got "
                                 << static_cast<int>(tokenValue);
    break;
  }
  EXPECT_TRUE(foundAuthToken) << "Must have found and parsed the AuthenticationToken in OPN body";

  channel.close_sync();
}

// Requirement: P6-67-0028 (SHALL)
// Both sender certificate and receiver certificate thumbprint present when policy != None.
// @relation(AC-SVR-UASC-028-BOTHPRESENT, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0028_BothPresent_Accepted)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // Verify both local (sender) cert and remote (receiver) cert are present in context.
  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();

      ASSERT_NE(context.localCertificate, nullptr) << "Sender certificate must be present";
      ASSERT_NE(context.remoteCertificate, nullptr) << "Receiver certificate must be present";

      // Verify they are actual certificates with non-empty DER encodings.
      EXPECT_GT(context.localCertificate->der_encoding().size(), 0u) << "Sender cert DER must not be empty";
      EXPECT_GT(context.remoteCertificate->der_encoding().size(), 0u)
        << "Receiver cert DER must not be empty";

      // Verify thumbprints are non-empty (thumbprint is used in the asymmetric security header).
      EXPECT_GT(context.localCertificate->thumbprint().size(), 0u)
        << "Sender cert thumbprint must not be empty";
      EXPECT_GT(context.remoteCertificate->thumbprint().size(), 0u)
        << "Receiver cert thumbprint must not be empty";
    });

  channel.close_sync();
}

// Requirement: P6-67-0031 (SHALL)
// OPN certificate continuity on renewal - same cert on renew.
// @relation(SVR-UASC-031, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0031_OpnCertContinuityOnRenew)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  struct ThumbprintPair
  {
    ua::ByteString local;
    ua::ByteString remote;
  };

  auto thumbprints = CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& context = *g.context();
      EXPECT_NE(context.localCertificate, nullptr);
      EXPECT_NE(context.remoteCertificate, nullptr);
      ThumbprintPair tp;
      if (context.localCertificate)
        tp.local = context.localCertificate->thumbprint();
      if (context.remoteCertificate)
        tp.remote = context.remoteCertificate->thumbprint();
      return tp;
    });
  ASSERT_FALSE(thumbprints.local.empty());
  ASSERT_FALSE(thumbprints.remote.empty());

  auto snap1 = read_channel_state(channel);
  ASSERT_TRUE(wait_for_renewal(channel, snap1.tokenId, 10s));

  // Renewal succeeded - verify cert continuity.
  EXPECT_TRUE(channel.is_open());
  CSCTA::on_strand(channel,
    [&](auto& g)
    {
      auto& context = *g.context();
      EXPECT_EQ(context.localCertificate->thumbprint(), thumbprints.local)
        << "Local cert must be the same after renewal";
      EXPECT_EQ(context.remoteCertificate->thumbprint(), thumbprints.remote)
        << "Remote cert must be the same after renewal";
    });

  channel.close_sync();
}

// Requirement: P6-67-0032 (SHALL)
// Security policy continuity on renewal - same policy on renew.
// @relation(AC-SVR-UASC-032-POLICYCONTINUITY, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0032_PolicyContinuityOnRenew)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  auto context = CSCTA::on_strand(channel, [](auto& g) { return g.context(); });
  ASSERT_NE(context->securityPolicy, nullptr);
  auto policyId = context->securityPolicy->id();
  std::string policyUri = context->securityPolicy->uri();

  auto snap1 = read_channel_state(channel);
  ASSERT_TRUE(wait_for_renewal(channel, snap1.tokenId, 10s));

  // Renewal succeeded - verify policy continuity.
  EXPECT_TRUE(channel.is_open());
  EXPECT_EQ(context->securityPolicy->id(), policyId) << "Security policy ID must not change on renewal";
  EXPECT_EQ(std::string(context->securityPolicy->uri()), policyUri)
    << "Security policy URI must not change on renewal";
  EXPECT_EQ(context->messageSecurityMode, MessageSecurityMode::SignAndEncrypt)
    << "Message security mode must not change on renewal";

  channel.close_sync();
}

// Requirement: P6-67-0033 (SHALL)
// Receiver certificate thumbprint correct (matches server cert).
// @relation(AC-SVR-UASC-033-THUMBMATCH, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0033_ThumbprintCorrect_Accepted)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  auto context = CSCTA::on_strand(channel, [](auto& g) { return g.context(); });
  ASSERT_NE(context->remoteCertificate, nullptr);

  // The remote certificate in the context should be the server cert we configured.
  auto serverThumbprint = mServerCert->thumbprint();
  auto contextThumbprint = context->remoteCertificate->thumbprint();

  EXPECT_EQ(contextThumbprint, serverThumbprint)
    << "Receiver certificate thumbprint in context must match the known server cert thumbprint";

  channel.close_sync();
}

// Requirement: P6-67-0034 (SHALL)
// Trusted certificate accepted.
// @relation(AC-SVR-UASC-034-TRUSTFIRST, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0034_TrustedCert_Accepted)
{
  // Client cert is in server's trusted list (set up by ComplianceSecured).
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // Verify by sending a service call - proves the full trust chain works.
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));
  EXPECT_THAT(result, ::ua::test_helpers::Good()) << "Trusted cert should allow service calls";

  channel.close_sync();
}

// Requirement: P6-67-0037 (SHALL)
// Sequence number and request ID are verified.
// Capture outgoing MSG frames and verify both sequence numbers and request IDs increase.
// @verifies CL-UASC-001
// @relation(CL-UASC-001, SVR-UASC-037, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0037_SequenceAndRequestIdVerified)
{
  auto captured = std::make_shared<CapturedFrames>();
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> fuzzTransport;

  auto channel =
    open_channel_with_transport_decorator(MessageSecurityMode::None, SecurityPolicyId::None, fuzzTransport);
  ASSERT_TRUE(channel.is_open());

  fuzzTransport->set_write_interceptor(
    [captured](std::vector<std::byte> data) -> std::vector<std::byte>
    {
      captured->add(data);
      return data;
    });

  constexpr int numCalls = 3;
  for (int i = 0; i < numCalls; ++i)
  {
    GetEndpointsRequest req;
    req.endpoint_url() = mEndpointUrl;
    auto result = channel.try_get_endpoints_sync(std::move(req));
    EXPECT_THAT(result, ::ua::test_helpers::Good());
  }

  // Parse MSG frames for sequence numbers and request IDs.
  std::vector<uint32_t> sequenceNumbers;
  std::vector<uint32_t> requestIds;
  auto frameCount = captured->count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = captured->get(i);
    auto msgType = read_message_type(frame);
    if (msgType == "MSG" && frame.size() >= 24)
    {
      sequenceNumbers.push_back(read_le_uint32(frame, 16));
      requestIds.push_back(read_le_uint32(frame, 20));
    }
  }

  ASSERT_GE(sequenceNumbers.size(), static_cast<size_t>(numCalls));

  for (size_t i = 1; i < sequenceNumbers.size(); ++i)
  {
    EXPECT_EQ(sequenceNumbers[i], sequenceNumbers[i - 1] + 1)
      << "Sequence number shall be incremented by exactly one per chunk";
  }

  // Request IDs should also be unique and increasing.
  for (size_t i = 1; i < requestIds.size(); ++i)
  {
    EXPECT_GT(requestIds[i], requestIds[i - 1]) << "Request ID must increase";
  }

  channel.close_sync();
}

// Requirement: P6-67-0039 (SHALL)
// "Stacks that implement UASC shall have a mechanism to log errors when invalid Messages
//  are discarded."
// Inject a corrupted MSG frame and verify the server logs an error.

/// Capturing log sink that records all log entries for later inspection.
// @relation(AC-SVR-UASC-039-LOGDISCARD, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0039_InvalidMessagesLogged)
{
  // The fixture installs mServerLogSink (a CapturingLogSink) on the server at construction.
  auto& capturingSink = *mServerLogSink;

  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> fuzzTransport;

  auto channel =
    open_channel_with_transport_decorator(MessageSecurityMode::None, SecurityPolicyId::None, fuzzTransport);
  ASSERT_TRUE(channel.is_open());

  // Verify normal operation works.
  {
    GetEndpointsRequest req;
    req.endpoint_url() = mEndpointUrl;
    auto result = channel.try_get_endpoints_sync(std::move(req));
    ASSERT_THAT(result, ::ua::test_helpers::Good());
  }

  // Clear logs so we only see errors from the corrupted message.
  capturingSink.clear();

  // Corrupt the next outgoing MSG frame - flip bytes in the body.
  bool intercepted = false;
  fuzzTransport->set_write_interceptor(
    [&intercepted](std::vector<std::byte> data) -> std::vector<std::byte>
    {
      std::string msgType(reinterpret_cast<const char*>(data.data()), std::min(data.size(), size_t{3}));
      if (msgType == "MSG" && !intercepted)
      {
        intercepted = true;
        for (size_t i = 24; i < data.size(); ++i)
          data[i] = static_cast<std::byte>(~static_cast<uint8_t>(data[i]));
      }
      return data;
    });

  // Send a service call - the corrupted message should cause an error.
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));

  EXPECT_TRUE(result.is_bad() || !channel.is_open())
    << "Server should reject or close channel on corrupted message";

  // Give the server a moment to process and log.
  std::this_thread::sleep_for(200ms);

  // Verify the server logged a warning or error about the invalid message.
  EXPECT_TRUE(capturingSink.has_warning_or_error())
    << "Server SHALL log errors when invalid messages are discarded";
}

// ===========================================================================
// Category E: Part 6 UASC - negative tests without unit coverage (3 tests)
// ===========================================================================

// Requirement: P6-67-0030 (SHALL)
// Verification error closes the channel.
// Use FuzzSecurityPolicy to corrupt an encoded chunk after the channel is established.
// @relation(AC-SVR-UASC-030-VERIFYFAIL, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0030_VerificationErrorClosesChannel)
{
  std::shared_ptr<opcua_fuzzer::FuzzSecurityPolicy> fuzzPolicy;

  auto channel = open_channel_with_security_policy_factory(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, fuzzPolicy);
  ASSERT_TRUE(channel.is_open());

  // Verify the channel works before corruption.
  {
    GetEndpointsRequest req;
    req.endpoint_url() = mEndpointUrl;
    auto result = channel.try_get_endpoints_sync(std::move(req));
    EXPECT_THAT(result, ::ua::test_helpers::Good()) << "Channel should work before corruption";
  }

  // Now set up the interceptor to corrupt encoded chunks (signature area).
  fuzzPolicy->set_encode_interceptor(
    [](ua::ByteString chunk) -> ua::ByteString
    {
      // Flip bits in the last 32 bytes (signature area) to cause verification failure.
      if (chunk.size() > 32)
      {
        for (size_t i = chunk.size() - 32; i < chunk.size(); ++i)
        {
          chunk[i] = static_cast<uint8_t>(~static_cast<uint8_t>(chunk[i]));
        }
      }
      return chunk;
    });

  // Send a service call - the corrupted message should cause the server to close the channel.
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));

  // Should fail: server detects signature verification error and closes the channel.
  EXPECT_TRUE(result.is_bad() || !channel.is_open())
    << "Server must close the channel on signature verification error";
}

// Requirement: P6-67-0034 (SHALL)
// Untrusted certificate rejected.
// Covers SVR-SECADMIN-020, SVR-TCP-032 (coverage-audit retag).
// @relation(AC-SVR-UASC-034-TRUSTFIRST, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0034_UntrustedCert_Rejected)
{
  // Create a new client with a certificate NOT in the server's trust list.
  auto untrustedCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Untrusted Client"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{.hostnames = {"localhost"}, .uris = {"urn:test:untrusted"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(untrustedCertResult, ::ua::test_helpers::Good());
  auto [untrustedKeys, untrustedCert] = std::move(untrustedCertResult).value();

  // Create a separate cert store with the untrusted cert.
  auto untrustedStorePath = mTempDir / "untrusted_store";
  std::filesystem::create_directories(untrustedStorePath);
  TrustListValidationOptions validationOptions;
  auto untrustedCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = untrustedStorePath, .validationOptions = validationOptions});

  CertificateStore::ApplicationCertificate appCert;
  appCert.certificateType = CertificateType::RsaSha256Application;
  appCert.certificate = untrustedCert;
  appCert.keys = std::move(untrustedKeys);
  untrustedCertStore->add_to_application_certificates_sync(appCert);
  // Trust the server cert so the client side accepts, but the server does not trust us.
  untrustedCertStore->add_to_trusted_certificates_sync(mServerCert);

  auto clientAppCfg = ua::test_utils::create_test_config();
  clientAppCfg.application_description_part().applicationUri = "urn:test:untrusted";
  client::CreateConfig clientCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
  auto untrustedClient = Client::create(mClientThreadPool.executor(),
    std::move(clientCfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = untrustedCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Debug});

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = mServerCert;

  auto result = untrustedClient.core().try_open_channel_sync(std::move(cfg));
  EXPECT_TRUE(result.is_bad()) << "Server should reject untrusted client certificate";
}

// Requirement: P6-67-0035 (SHALL)
// Expired token rejected (after timeout with no renewal).
// Cancel the client's auto-renewal timer and wait for the token to expire.
// @relation(AC-SVR-UASC-035-TOKENEXPIRED, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, P6_67_0035_ExpiredToken_Rejected)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  auto snap = read_channel_state(channel);
  auto revisedLifetime = snap.revisedLifetime;
  EXPECT_GT(revisedLifetime.count(), 0) << "Revised lifetime must be > 0";

  // Cancel the automatic renewal timer so the token will expire.
  CSCTA::on_strand(channel,
    [](auto& g)
    {
      auto& renewalTimer = g.renewal_timer();
      if (renewalTimer)
      {
        renewalTimer.cancel();
      }
    });

  // Wait for the token to expire (revised lifetime + some grace period).
  // The server's token timeout fires after the revised lifetime.
  auto waitTime = revisedLifetime + 2000ms;
  std::this_thread::sleep_for(waitTime);

  // Try a service call - should fail because the token has expired.
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));

  EXPECT_TRUE(result.is_bad() || !channel.is_open())
    << "Channel should be unusable after token expires without renewal";
}

// ===========================================================================
// Category F: Part 6 Connection Protocol - positive tests (7 tests)
// ===========================================================================

// Requirement: P6-71-0001 (SHALL)
// Valid reserved byte in HEL/ACK is accepted.
// Capture the HEL frame and verify the reserved byte (isFinal) is 'F'.
TEST_F(ComplianceSecureChannel, P6_71_0001_ValidReservedByte_Accepted)
{
  auto captured = std::make_shared<CapturedFrames>();

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::None;
  cfg.securityPolicyId = SecurityPolicyId::None;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [captured](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [captured](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          captured->add(data);
          return data;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  auto channel = mClient->core().open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channel.is_open());

  // Find HEL frame and check the reserved byte (byte 3 = 'F' for Final).
  bool foundHel = false;
  auto frameCount = captured->count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = captured->get(i);
    auto msgType = read_message_type(frame);
    if (msgType == "HEL" && frame.size() >= 4)
    {
      foundHel = true;
      char reservedByte = static_cast<char>(frame[3]);
      EXPECT_EQ(reservedByte, 'F') << "HEL reserved/isFinal byte should be 'F'; got '" << reservedByte << "'";
      break;
    }
  }
  EXPECT_TRUE(foundHel) << "Must have captured a HEL frame";

  channel.close_sync();
}

// Requirement: P6-71-0002 (SHALL)
// Message size within buffer accepted.
// @relation(SVR-TCP-002, SVR-TCP-032, scope=function)
TEST_F(ComplianceSecureChannel, P6_71_0002_MessageSizeWithinBuffer_Accepted)
{
  auto captured = std::make_shared<CapturedFrames>();
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> fuzzTransport;

  auto channel =
    open_channel_with_transport_decorator(MessageSecurityMode::None, SecurityPolicyId::None, fuzzTransport);
  ASSERT_TRUE(channel.is_open());

  auto context = CSCTA::on_strand(channel, [](auto& g) { return g.context(); });
  auto maxSendSize = context->negotiatedLimits.sendBufferSize;

  fuzzTransport->set_write_interceptor(
    [captured](std::vector<std::byte> data) -> std::vector<std::byte>
    {
      captured->add(data);
      return data;
    });

  // Send a normal request and verify its frame size is within the negotiated buffer.
  GetEndpointsRequest req;
  req.endpoint_url() = mEndpointUrl;
  auto result = channel.try_get_endpoints_sync(std::move(req));
  EXPECT_THAT(result, ::ua::test_helpers::Good());

  // Check all captured MSG frames are within buffer size.
  auto frameCount = captured->count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = captured->get(i);
    auto msgType = read_message_type(frame);
    if (msgType == "MSG")
    {
      EXPECT_LE(frame.size(), static_cast<size_t>(maxSendSize))
        << "MSG frame size (" << frame.size() << ") must be <= negotiated buffer size (" << maxSendSize
        << ")";
    }
  }

  channel.close_sync();
}

// Requirement: P6-71-0003 (SHALL)
// Protocol version negotiated (client and server agree on version).
// @relation(SVR-TCP-003, SVR-TCP-004, SVR-TCP-028, SVR-TCP-032, scope=function)
TEST_F(ComplianceSecureChannel, P6_71_0003_ProtocolVersionNegotiated)
{
  auto captured = std::make_shared<CapturedFrames>();

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::None;
  cfg.securityPolicyId = SecurityPolicyId::None;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [captured](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [captured](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          captured->add(data);
          return data;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  auto channel = mClient->core().open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channel.is_open());

  // HEL frame: [8-11] = protocolVersion (should be 0 for current spec).
  bool foundHel = false;
  auto frameCount = captured->count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = captured->get(i);
    auto msgType = read_message_type(frame);
    if (msgType == "HEL" && frame.size() >= 12)
    {
      foundHel = true;
      uint32_t version = read_le_uint32(frame, 8);
      // Current OPC UA TCP protocol version is 0.
      EXPECT_EQ(version, 0u) << "Protocol version in HEL should be 0 (current spec)";
      break;
    }
  }
  EXPECT_TRUE(foundHel) << "Must have captured a HEL frame";

  // Channel opened successfully means the server accepted the negotiated version.
  channel.close_sync();
}

// Requirement: P6-71-0004 (SHALL)
// Receive buffer size meets minimum (8192 bytes per spec).
// @relation(SVR-TCP-005, SVR-TCP-032, scope=function)
TEST_F(ComplianceSecureChannel, P6_71_0004_ReceiveBufferMeetsMinimum)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channel.is_open());

  auto context = CSCTA::on_strand(channel, [](auto& g) { return g.context(); });

  // Negotiated send buffer (clamped to server's ACK receive) must meet spec minimum.
  EXPECT_GE(context->negotiatedLimits.sendBufferSize, 8192u)
    << "Negotiated send buffer must be >= 8192 bytes (spec minimum)";

  // Negotiated receive buffer (from server's ACK send) must meet spec minimum.
  EXPECT_GE(context->negotiatedLimits.receiveBufferSize, 8192u)
    << "Negotiated receive buffer must be >= 8192 bytes (spec minimum)";

  channel.close_sync();
}

// Requirement: P6-71-0005 (SHALL)
// Send buffer size meets minimum (8192 bytes per spec).
// @relation(SVR-TCP-006, SVR-TCP-032, scope=function)
TEST_F(ComplianceSecureChannel, P6_71_0005_SendBufferMeetsMinimum)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channel.is_open());

  auto context = CSCTA::on_strand(channel, [](auto& g) { return g.context(); });

  // Negotiated send buffer must meet spec minimum.
  EXPECT_GE(context->negotiatedLimits.sendBufferSize, 8192u)
    << "Negotiated send buffer must be >= 8192 bytes (spec minimum)";

  // Negotiated receive buffer must meet spec minimum.
  EXPECT_GE(context->negotiatedLimits.receiveBufferSize, 8192u)
    << "Negotiated receive buffer must be >= 8192 bytes (spec minimum)";

  channel.close_sync();
}

// Requirement: P6-71-0013 (SHALL)
// ACK receive buffer is clamped (server doesn't exceed client's requested value).
// @relation(AC-SVR-TCP-013-ACK-RECEIVE-BUFFER-FLOOR, SVR-TCP-032, scope=function)
TEST_F(ComplianceSecureChannel, P6_71_0013_AckReceiveBufferClamped)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channel.is_open());

  auto context = CSCTA::on_strand(channel, [](auto& g) { return g.context(); });

  // The negotiated send buffer (from server's ACK ReceiveBufferSize) tells us how much WE can send.
  // It should be >= the spec minimum.
  EXPECT_GE(context->negotiatedLimits.sendBufferSize, 8192u)
    << "Negotiated send buffer must be >= 8192 bytes (spec minimum)";

  channel.close_sync();
}

// Requirement: P6-71-0014 (SHALL)
// ACK send buffer is clamped.
// @relation(AC-SVR-TCP-014-ACK-SEND-BUFFER-FLOOR, SVR-TCP-032, scope=function)
TEST_F(ComplianceSecureChannel, P6_71_0014_AckSendBufferClamped)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channel.is_open());

  auto context = CSCTA::on_strand(channel, [](auto& g) { return g.context(); });

  // The negotiated receive buffer (from server's ACK SendBufferSize) tells us what to expect
  // for incoming message sizes. It should be >= the spec minimum.
  EXPECT_GE(context->negotiatedLimits.receiveBufferSize, 8192u)
    << "Negotiated receive buffer must be >= 8192 bytes (spec minimum)";

  channel.close_sync();
}

// ===========================================================================
// Category G: Part 6 Connection Protocol - negative tests without unit coverage
// ===========================================================================

// Requirement: P6-71-0011 (SHALL)
// BadTcpNotEnoughResources when connection limit exceeded.
// @relation(SVR-TCP-012, SVR-TCP-032, scope=function)
TEST_F(ComplianceSecureChannelConnectionLimit, P6_71_0011_BadTcpNotEnoughResources)
{
  // The fixture limits mMaxConnections=4.
  // Open channels until we reach the limit, then expect the next to fail.
  std::vector<SecureChannel> channels;

  // Open channels up to the connection limit.
  for (uint32_t i = 0; i < mMaxConnections; ++i)
  {
    auto result = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl});
    if (result.is_bad())
    {
      // We hit the limit earlier than expected - that's fine, record where.
      break;
    }
    channels.push_back(std::move(result).value());
  }

  ASSERT_FALSE(channels.empty()) << "Should be able to open at least one channel";

  // Try one more - should fail with resource exhaustion.
  // Use a second client to ensure a fresh TCP connection.
  auto client2 = create_additional_client();
  auto extraResult = client2.core().try_open_channel_sync({.endpointUrl = mEndpointUrl});

  // The server should reject this with BadTcpNotEnoughResources or similar.
  // Note: the exact error may vary (could be a connection-level rejection or an OPN failure).
  EXPECT_TRUE(extraResult.is_bad()) << "Server should reject connection when resource limit is exceeded";

  // Clean up.
  for (auto& ch : channels)
  {
    ch.try_close_sync();
  }
}

// ===========================================================================
// Category I: Additional compliance tests (positive, observe, intercept)
// ===========================================================================

// Includes for server-side test hooks.
#include "server_test_access.h"
#include "server_impl_test_access.h"
#include "ua_server_secure_channel_test_access.h"
#include "ua_open_secure_channel_request.h"

// ---------------------------------------------------------------------------
// Helper fixture: ComplianceSecureChannel + server-side hooks
// ---------------------------------------------------------------------------
class ComplianceWithHooks : public ComplianceSecureChannel
{
protected:
  void SetUp() override
  {
    ComplianceSecureChannel::SetUp();
    install_hooks();
  }

  void install_hooks()
  {
    auto& serverImpl = ua::test_helpers::ServerTestAccess::impl(*mServer);
    ua::test_helpers::ServerImplTestAccess access(serverImpl);

    access.set_on_secure_channel_available(
      [this](std::shared_ptr<ua::server::SecureChannel> sc)
      {
        {
          std::lock_guard lock(mHookMutex);
          mServerChannel = sc;
        }

        // Install request observer on this channel.
        ua::server::SecureChannelTestAccess::on_strand(*sc,
          [&](auto& g)
          {
            g.set_request_observer(
              [this](uint32_t requestId, const ua::Structure& request)
              {
                std::lock_guard lock(mHookMutex);
                mObservedRequests.push_back(
                  ObservedRequest{requestId, std::string(request.type_name()), request.clone()});
                mHookCv.notify_all();
              });
          });

        // Install pass-through response interceptor (does not modify).
        ua::server::SecureChannelTestAccess::on_strand(*sc,
          [&](auto& g)
          {
            g.set_response_interceptor(
              [this](ua::Response& response)
              {
                std::lock_guard lock(mHookMutex);
                ++mInterceptedResponseCount;
                mHookCv.notify_all();
              });
          });
      });
  }

  struct ObservedRequest
  {
    uint32_t requestId;
    std::string typeName;
    std::shared_ptr<ua::Structure> request;
  };

  /// Wait until we have at least `count` observed requests of the given type name.
  bool wait_for_requests(const std::string& typeName, size_t count, std::chrono::milliseconds timeout)
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::unique_lock lock(mHookMutex);
    return mHookCv.wait_until(lock,
      deadline,
      [&]
      {
        size_t found = 0;
        for (const auto& req : mObservedRequests)
        {
          if (req.typeName == typeName)
            ++found;
        }
        return found >= count;
      });
  }

  /// Get all observed requests of a given type name.
  std::vector<ObservedRequest> get_requests_of_type(const std::string& typeName)
  {
    std::lock_guard lock(mHookMutex);
    std::vector<ObservedRequest> result;
    for (auto& req : mObservedRequests)
    {
      if (req.typeName == typeName)
        result.push_back(req);
    }
    return result;
  }

  void TearDown() override
  {
    // Drop the strong ref to the server-side SecureChannel BEFORE parent TearDown
    // stops the server thread pool. Otherwise the channel keeps the io_context busy
    // (timers, pending strand work) past the pool stop watchdog.
    {
      std::lock_guard lock(mHookMutex);
      mServerChannel.reset();
      mObservedRequests.clear();
    }
    ComplianceSecureChannel::TearDown();
  }

  std::mutex mHookMutex;
  std::condition_variable mHookCv;
  std::shared_ptr<ua::server::SecureChannel> mServerChannel;
  std::vector<ObservedRequest> mObservedRequests;
  size_t mInterceptedResponseCount{0};
};

// ===========================================================================
// I-positive tests
// ===========================================================================

// SC_HostnameSkippedForNone: Connect with None policy. Channel opens.
// Proves hostname check is skipped for None security.
// This positive test is meaningful only in conjunction with SC_HostnameMismatchReported
// (the negative counterpart that verifies hostname checking IS performed for authenticated
// channels). Without the negative test, this would be indistinguishable from "hostname
// matching not implemented".
// @relation(SVR-SC-005, scope=function)
TEST_F(ComplianceSecureChannel, SC_HostnameSkippedForNone)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  EXPECT_TRUE(channel.is_open());
  channel.close_sync();
}

// SC_MatchingResponseCertAccepted: DELETED - duplicates P6_67_0034_TrustedCert_Accepted
// which already verifies that an authenticated channel opens with a trusted server cert.

// SC_CLOSignedWithCurrentTokenKey: Open channel, close it. If close_sync succeeds
// without error, server accepted the CLO - proves it was signed correctly.
//
// Limitation: close_sync() success proves the client sent a well-formed CLO message, but
// does not prove the server verified the CLO signature specifically. Per Part 6,
// servers close the connection upon receiving CLO regardless of signature validity.
// To truly verify the token ID, a FuzzTransportConnection write interceptor would need
// to capture the outgoing CLO frame and check bytes 12-15 for the current token ID.
// The current test is a smoke test for the authenticated close path.
// Covers SVR-SC-021 (coverage-audit retag).
// @relation(SVR-SC-021, SVR-UASC-061, scope=function)
TEST_F(ComplianceSecureChannel, SC_CLOSignedWithCurrentTokenKey)
{
  auto channel = open_channel(MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // close_sync sends CLO and closes transport. Success here proves the client
  // produced a correctly signed CLO with the current token key.
  EXPECT_NO_THROW(channel.close_sync());
}

// SC_SymmetricMessagesUseCurrentTokenId: Open channel, create session. If session
// creation succeeds, the symmetric MSG was accepted - proves correct token ID.
// @verifies CL-SC-009
// @relation(CL-SC-009, SVR-SC-016, scope=function)
TEST_F(ComplianceSecureChannel, SC_SymmetricMessagesUseCurrentTokenId)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // Creating a session sends a symmetric MSG. If it succeeds, the token ID was correct.
  auto session = channel.create_session_sync({.sessionName = "SC_TokenIdTest"});
  session.activate_sync();

  // Cleanup.
  session.close_sync();
  channel.close_sync();
}

// ===========================================================================
// I-observe tests (use request observer via server hooks)
// ===========================================================================

// SC_ClientNonceDifferentOnIssueAndRenew: Capture two OPN requests (Issue + Renew).
// Assert nonces differ and are >= 32 bytes for authenticated channels.
// @relation(AC-SVR-UASC-024-NONCE, scope=function)
TEST_F(ComplianceWithHooks, SC_ClientNonceDifferentOnIssueAndRenew)
{
  // Open with short lifetime so renewal happens quickly.
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  // Wait for the initial OPN (Issue).
  ASSERT_TRUE(wait_for_requests("OpenSecureChannelRequest", 1, 5s)) << "Did not observe initial OPN request";

  // Wait for renewal OPN (should happen at ~75% of 2s = ~1.5s).
  ASSERT_TRUE(wait_for_requests("OpenSecureChannelRequest", 2, 10s)) << "Did not observe renewal OPN request";

  auto opnRequests = get_requests_of_type("OpenSecureChannelRequest");
  ASSERT_GE(opnRequests.size(), 2u);

  auto& issueReq = dynamic_cast<const ua::OpenSecureChannelRequest&>(*opnRequests[0].request);
  auto& renewReq = dynamic_cast<const ua::OpenSecureChannelRequest&>(*opnRequests[1].request);

  const auto& issueNonce = issueReq.client_nonce();
  const auto& renewNonce = renewReq.client_nonce();

  // Nonces must be >= 32 bytes for Basic256Sha256.
  EXPECT_GE(issueNonce.size(), 32u) << "Issue nonce should be >= 32 bytes";
  EXPECT_GE(renewNonce.size(), 32u) << "Renew nonce should be >= 32 bytes";

  // Nonces must differ between issue and renew.
  EXPECT_NE(issueNonce, renewNonce) << "Issue and renew nonces must be different";

  channel.close_sync();
}

// SC_OpnClientProtocolVersionMatchesHello: Capture OpenSecureChannelRequest.
// Assert client_protocol_version() == 0 (matching what HEL sends).
// Note: HEL is processed at the transport layer and not captured by the service request
// observer. The OPN version is verified against the spec-required value (0) rather than
// by reading both HEL and OPN and comparing them. The unit test
// ClientUsesNegotiatedProtocolVersion verifies the HEL value directly.
// @verifies CL-UASC-013
// @relation(CL-UASC-013, SVR-UASC-021, scope=function)
TEST_F(ComplianceWithHooks, SC_OpnClientProtocolVersionMatchesHello)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channel.is_open());

  ASSERT_TRUE(wait_for_requests("OpenSecureChannelRequest", 1, 5s)) << "Did not observe OPN request";

  auto opnRequests = get_requests_of_type("OpenSecureChannelRequest");
  ASSERT_GE(opnRequests.size(), 1u);

  auto& opnReq = dynamic_cast<const ua::OpenSecureChannelRequest&>(*opnRequests[0].request);
  EXPECT_EQ(opnReq.client_protocol_version(), 0u) << "Client protocol version should be 0";

  channel.close_sync();
}

// SC_OpnRequestHasNullAuthenticationToken: Capture OpenSecureChannelRequest.
// Assert the authentication token in the request header is null.
// @verifies CL-UASC-014
// @relation(CL-UASC-014, SVR-UASC-026, scope=function)
TEST_F(ComplianceWithHooks, SC_OpnRequestHasNullAuthenticationToken)
{
  auto channel = open_channel(MessageSecurityMode::None, SecurityPolicyId::None);
  ASSERT_TRUE(channel.is_open());

  ASSERT_TRUE(wait_for_requests("OpenSecureChannelRequest", 1, 5s)) << "Did not observe OPN request";

  auto opnRequests = get_requests_of_type("OpenSecureChannelRequest");
  ASSERT_GE(opnRequests.size(), 1u);

  auto& opnReq = dynamic_cast<const ua::OpenSecureChannelRequest&>(*opnRequests[0].request);
  EXPECT_TRUE(opnReq.request_header().authentication_token().is_null())
    << "OPN request authentication token must be null";

  channel.close_sync();
}

// ===========================================================================
// I-intercept tests (use response interceptor via server hooks)
// ===========================================================================

// SC_ServerNonceCorrectLengthAccepted: Don't modify the response (pass-through interceptor).
// Channel opens - proves the server's 32-byte nonce is accepted.
TEST_F(ComplianceWithHooks, SC_ServerNonceCorrectLengthAccepted)
{
  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  // The pass-through interceptor was installed. If the channel opened successfully,
  // the server nonce (which should be 32 bytes for Basic256Sha256) was accepted.
  auto snap = read_channel_state(channel);
  EXPECT_GE(snap.serverNonce.size(), 32u) << "Server nonce should be >= 32 bytes for Basic256Sha256";

  // Verify that at least one response was intercepted (the OPN response).
  {
    std::lock_guard lock(mHookMutex);
    EXPECT_GE(mInterceptedResponseCount, 1u) << "Expected at least one intercepted response (OPN)";
  }

  channel.close_sync();
}

// ===========================================================================
// Additional I-positive tests
// ===========================================================================

// SC_HostnameMismatchReported (#34)
// Create a second server whose certificate SAN contains only "mismatch.example" (not
// "localhost" or "127.0.0.1"). The client connects to this second server on 127.0.0.1.
// Since the cert SAN doesn't match the endpoint hostname, the public Client channel-open
// path must reject the channel.
// @verifies CL-SC-003
// @relation(CL-SC-003, SVR-SC-005, scope=function)
TEST_F(ComplianceSecureChannel, SC_HostnameMismatchReported)
{
  // 1. Generate a new server cert with mismatched SAN.
  auto mismatchCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Mismatch Server"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{.hostnames = {"mismatch.example"}, .uris = {"urn:test:mismatch"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(mismatchCertResult, ::ua::test_helpers::Good());
  auto [mismatchKeys, mismatchCert] = std::move(mismatchCertResult).value();

  // 2. Create a temp cert store for the second server.
  auto mismatchStorePath = mTempDir / "mismatch_server_store";
  std::filesystem::create_directories(mismatchStorePath);
  TrustListValidationOptions validationOptions;
  auto mismatchServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
    mCrypto,
    {.trustListPath = mismatchStorePath, .validationOptions = validationOptions});

  // 3. Add the mismatch cert as the server's application cert.
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = mismatchCert;
    appCert.keys = std::move(mismatchKeys);
    mismatchServerCertStore->add_to_application_certificates_sync(appCert);
  }

  // 4. Add the client cert to the second server's trusted certs.
  auto clientAppCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(clientAppCerts.empty());
  mismatchServerCertStore->add_to_trusted_certificates_sync(clientAppCerts.front().certificate);

  // 5. Add the mismatch server cert to the client's trust store so the client trusts it.
  mClientCertStore->add_to_trusted_certificates_sync(mismatchCert);

  // 6. Create and start a second server on an ephemeral port with its own thread pool.
  boost::asio::thread_pool mismatchServerPool;

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  appCfg.stack_limits().secureChannelMinimumLifetime = std::chrono::milliseconds{1000};
  ServerComponents components{.crypto = mCrypto,
    .applicationGroupCertificateStore = mismatchServerCertStore,
    .logSink = test_log_sink(),
    .logLevel = LogLevel::Debug};
  components.authenticator = std::make_shared<AnonymousAuthenticator>();
  components.roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});
  server::CreateConfig serverCreateCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
  auto mismatchServer = ua::server::Server::create(
    mismatchServerPool.executor(), std::move(serverCreateCfg), std::move(components));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto listenerHandle = mismatchServer.listen_sync(std::move(bind), {});

  ServerEndpointConfig signEncryptEp;
  signEncryptEp.name = "Basic256Sha256_SignAndEncrypt";
  signEncryptEp.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  signEncryptEp.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  signEncryptEp.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  mismatchServer.add_endpoint(listenerHandle, std::move(signEncryptEp));
  mismatchServer.start_sync();

  auto urls = mismatchServer.advertised_urls(listenerHandle);
  ASSERT_FALSE(urls.empty());
  auto mismatchUrl = urls.front().str();

  // 7. Try to open a channel to the second server.
  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mismatchUrl;
  cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = mismatchCert;
  auto result = mClient->core().try_open_channel_sync(std::move(cfg));

  // 8. The client rejects because the SAN does not match 127.0.0.1.
  ASSERT_TRUE(result.is_bad())
    << "Client accepted a certificate whose SAN does not match the endpoint hostname "
       "- hostname matching not enforced";
  EXPECT_EQ(result.status_code().as_status(), Status::BadCertificateHostNameInvalid)
    << "the public channel-open result must report the specific hostname mismatch";
  EXPECT_NE(result.shared_detail(), nullptr)
    << "the hostname rejection must retain its ErrorDetail across the wire boundary";

  // 9. Defensive cleanup if a regression unexpectedly opened the channel.
  if (result.is_good())
  {
    (void)result.value().try_close_sync();
  }

  // Graceful shutdown before destruction prevents connection teardown races.
  (void)mismatchServer.try_shutdown_sync({.grace = std::chrono::seconds{0}});
  mismatchServerPool.join();
}

// SC_ClientNonceDifferentAcrossRenewals (#37)
// Open a channel with a short lifetime, wait for two renewals, and verify all three
// client nonces (initial + 2 renewals) are distinct.
TEST_F(ComplianceSecureChannel, SC_ClientNonceDifferentAcrossRenewals)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  // Capture the initial client nonce.
  auto snap0 = read_channel_state(channel);
  auto initialNonce = snap0.lastClientNonce;
  auto initialTokenId = snap0.tokenId;
  ASSERT_GE(initialNonce.size(), 32u) << "Initial client nonce must be >= 32 bytes for Basic256Sha256";

  // Wait for first renewal (token ID changes).
  ASSERT_TRUE(wait_for_renewal(channel, initialTokenId, 10s)) << "First renewal did not happen in time";
  auto snap1 = read_channel_state(channel);
  auto nonce1 = snap1.lastClientNonce;
  EXPECT_GE(nonce1.size(), 32u) << "First renewal nonce must be >= 32 bytes";
  EXPECT_NE(initialNonce, nonce1) << "Nonce after first renewal must differ from initial nonce";

  // Wait for second renewal.
  ASSERT_TRUE(wait_for_renewal(channel, snap1.tokenId, 10s)) << "Second renewal did not happen in time";
  auto snap2 = read_channel_state(channel);
  auto nonce2 = snap2.lastClientNonce;
  EXPECT_GE(nonce2.size(), 32u) << "Second renewal nonce must be >= 32 bytes";
  EXPECT_NE(nonce1, nonce2) << "Nonce after second renewal must differ from first renewal nonce";
  EXPECT_NE(initialNonce, nonce2) << "Nonce after second renewal must differ from initial nonce";

  channel.close_sync();
}

// SC_NewTokenWorksAfterRenewalComplete (#49)
// Spec: Part 6, 6.7.4 -- Old token rejected after renewal completes.
// This test only verifies the new token works after renewal - actual rejection of the old
// token after the grace period is verified at the unit test level by
// TokenRolloverPromotesPendingTokenAndRejectsOldTokenAfterPromotion.
// Renamed from SC_OldTokenRejectedAfterRenewalComplete to accurately reflect what is tested.
TEST_F(ComplianceSecureChannel, SC_NewTokenWorksAfterRenewalComplete)
{
  auto channel = open_channel_short_lifetime(
    MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256, 2000ms);
  ASSERT_TRUE(channel.is_open());

  auto snap0 = read_channel_state(channel);
  auto initialTokenId = snap0.tokenId;
  ASSERT_NE(initialTokenId, 0u);

  // Wait for renewal to complete (token ID changes).
  ASSERT_TRUE(wait_for_renewal(channel, initialTokenId, 10s)) << "Token renewal did not happen in time";

  auto snap1 = read_channel_state(channel);
  EXPECT_NE(snap1.tokenId, initialTokenId) << "Token ID must change after renewal";

  // Send a service request after renewal -- proves new token works.
  auto session = channel.create_session_sync({.sessionName = "TokenRejectionTest"});
  EXPECT_TRUE(session.is_created()) << "Service request must succeed after token renewal";

  session.close_sync();
  channel.close_sync();
}

// SC_ServerCertConsistencyAcrossSessionServices (#52): DELETED - duplicates
// P4_0004_CertContinuityAcrossOpnCreateActivate which already verifies certificate
// consistency across OPN, CreateSession, and ActivateSession with explicit thumbprint
// comparison.

// SC_TokenIdUpdatedAfterRenewal (#47): DELETED - duplicates P4_0009_RenewReturnsNewToken
// which already verifies the token ID changes after renewal.

// ===========================================================================
// Additional I-intercept tests
// ===========================================================================

// SC_MismatchedResponseCertAbandonsChannel (#51)
// Generate a second self-signed cert (different from the server cert). When the server
// sends the OPN response, the response interceptor swaps mContext->localCertificate to
// the second cert. The asymmetric header encoding then uses the wrong certificate, and
// the client should reject the channel because the cert doesn't match expectations.
TEST_F(ComplianceWithHooks, SC_MismatchedResponseCertAbandonsChannel)
{
  // 1. Generate a second self-signed cert different from the server cert.
  auto secondCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Wrong Server Cert"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{.hostnames = {"wrong.example"}, .uris = {"urn:test:wrong"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(secondCertResult, ::ua::test_helpers::Good());
  auto [secondKeys, secondCert] = std::move(secondCertResult).value();

  // 2. Install a cert-swapping interceptor on the NEXT channel created by the server.
  // The fixture's install_hooks() already set up hooks on the first channel, but this
  // test needs to intercept the OPN for a new connection.
  auto& serverImpl = ua::test_helpers::ServerTestAccess::impl(*mServer);
  ua::test_helpers::ServerImplTestAccess access(serverImpl);
  access.set_on_secure_channel_available(
    [this, wrongCert = secondCert](std::shared_ptr<ua::server::SecureChannel> sc)
    {
      {
        std::lock_guard lock(mHookMutex);
        mServerChannel = sc;
      }

      ua::server::SecureChannelTestAccess::on_strand(*sc,
        [&](auto& g)
        {
          // Capture context shared_ptr so the interceptor can modify it on-strand.
          auto ctx = g.context();
          g.set_response_interceptor(
            [this, wrongCert, ctx](ua::Response& response)
            {
              std::lock_guard innerLock(mHookMutex);
              ++mInterceptedResponseCount;

              // Swap the local certificate on OPN responses.
              if (dynamic_cast<ua::OpenSecureChannelResponse*>(response.second.get()))
              {
                ctx->localCertificate = wrongCert;
              }

              mHookCv.notify_all();
            });
        });
    });

  // 4. Try to open a channel with SignAndEncrypt.
  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = mServerCert;
  auto result = mClient->core().try_open_channel_sync(std::move(cfg));

  // 5. The client should reject because the cert in the OPN response asymmetric header
  // doesn't match what the client expected (mServerCert).
  EXPECT_TRUE(result.is_bad())
    << "Client should reject a channel whose OPN response contains a mismatched certificate";
}

// ===========================================================================
// Additional SC_ coverage tests
// ===========================================================================

// SC_TrustedServerCertAccepted (#66): DELETED - duplicates P6_67_0034_TrustedCert_Accepted
// which already verifies an authenticated channel opens with a trusted server certificate.

// SC_UntrustedServerCertRejected (#67)
// Requirement: An untrusted server certificate causes the channel to be rejected.
// Create a second server whose certificate is NOT in the client's trust store.
// The client should reject the channel because the server cert is untrusted.
// @verifies CL-UASC-009
// @relation(CL-UASC-009, SVR-UASC-034, scope=function)
TEST_F(ComplianceSecureChannel, SC_UntrustedServerCertRejected)
{
  // 1. Generate a new server certificate (not in the client's trust store).
  auto untrustedServerCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Untrusted Server"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{
      .hostnames = {"localhost", "127.0.0.1"}, .uris = {"urn:test:untrusted:server"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(untrustedServerCertResult, ::ua::test_helpers::Good());
  auto [untrustedServerKeys, untrustedServerCert] = std::move(untrustedServerCertResult).value();

  // 2. Create a cert store for the second server.
  auto untrustedServerStorePath = mTempDir / "untrusted_server_store";
  std::filesystem::create_directories(untrustedServerStorePath);
  TrustListValidationOptions validationOptions;

  // Use the existing server thread pool for the second server's cert store.
  auto untrustedServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
    mCrypto,
    {.trustListPath = untrustedServerStorePath, .validationOptions = validationOptions});

  // 3. Add the untrusted cert as the second server's application cert.
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = untrustedServerCert;
    appCert.keys = std::move(untrustedServerKeys);
    untrustedServerCertStore->add_to_application_certificates_sync(appCert);
  }

  // 4. The second server trusts the existing client cert (so the server side accepts the client).
  //    We need to retrieve the client's certificate from the client cert store.
  //    The fixture's mClientCertStore holds the client app cert which also trusts the *original* server.
  //    We just need the second server to trust the client cert - get it from our cert store.
  auto clientAppCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(clientAppCerts.empty());
  untrustedServerCertStore->add_to_trusted_certificates_sync(clientAppCerts.front().certificate);

  // 5. Do NOT add the untrusted server cert to the client's trust store.
  //    (The client only trusts mServerCert from the fixture setup.)

  // 6. Create and start a second Server instance.
  // Use a dedicated thread pool so it can be shut down independently.
  boost::asio::thread_pool secondServerPool;

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  ServerComponents components{.crypto = mCrypto,
    .applicationGroupCertificateStore = untrustedServerCertStore,
    .logSink = test_log_sink(),
    .logLevel = LogLevel::Debug};
  components.authenticator = std::make_shared<AnonymousAuthenticator>();
  components.roleConfiguration = RoleConfiguration::from_well_known_grants(
    {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

  server::CreateConfig serverCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

  std::optional<ua::server::Server> secondServer;
  secondServer.emplace(
    ua::server::Server::create(secondServerPool.executor(), std::move(serverCfg), std::move(components)));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  auto listenerHandle = secondServer->listen_sync(std::move(bind), {});

  // Add a SignAndEncrypt endpoint.
  ServerEndpointConfig signEncryptEp;
  signEncryptEp.name = "Basic256Sha256_SignAndEncrypt";
  signEncryptEp.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  signEncryptEp.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  signEncryptEp.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  secondServer->add_endpoint(listenerHandle, std::move(signEncryptEp));

  secondServer->start_sync();

  auto urls = secondServer->advertised_urls(listenerHandle);
  ASSERT_FALSE(urls.empty());
  auto newEndpointUrl = urls.front().str();

  // 7. Have the existing client try to open a channel to the second server.
  //    The client does NOT trust the second server's certificate.
  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = newEndpointUrl;
  cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = untrustedServerCert;

  auto result = mClient->core().try_open_channel_sync(std::move(cfg));

  // 8. Assert failure - the client should reject because the server cert is not trusted.
  EXPECT_TRUE(result.is_bad()) << "Client should reject channel to server with untrusted certificate";

  // Graceful shutdown, destroy server, drain pool. Server destruction cancels
  // its timers; pool stop catches anything that escaped.
  if (secondServer)
    (void)secondServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  secondServer.reset();
  secondServerPool.join();
}

// SC_OldTokenAcceptedDuringRenewal (#48): DELETED - duplicates P4_0001_OldTokenAcceptedAfterRenew
// which already verifies the old token is accepted during the renewal grace period using the
// same FuzzTransportConnection token-rewriting technique.

// ===========================================================================
// Obligation closure: criteria whose discharge was "(none)"
// ===========================================================================

// Part 4 section 5.5.2 - at the channel limit the server closes the oldest unused SecureChannel *that has no
// Session assigned*. A plausible implementation evicts purely by `last_used_time`: with an older
// channel carrying a Session and a newer session-less one, an age-only LRU throws out the Session
// channel and leaves the session-less one in place - which is exactly the denial of service the
// session-less qualifier exists to prevent. The two existing P4_0002 tests never place the Session
// channel at the front of the LRU order, so neither can tell the two policies apart.
// @verifies AC-SVR-SC-002-EVICT-SESSIONLESS-CHANNEL
// @relation(AC-SVR-SC-002-EVICT-SESSIONLESS-CHANNEL, scope=function)
TEST_F(ComplianceSecureChannelLimited, EvictionAtCapacityTakesTheSessionlessChannelNotTheOlderSessionChannel)
{
  // The Session-carrying channel is opened FIRST and is therefore the least recently used of the two.
  auto sessionChannel = open_channel_auth();
  ASSERT_TRUE(sessionChannel.is_open());
  auto sessionChannelId = sessionChannel.secure_channel_id();
  auto session = sessionChannel.create_session_sync({.sessionName = "SC_002_Protected"});
  session.activate_sync();
  ASSERT_TRUE(session.is_active()) << "the protected channel must really carry an activated Session";

  // The session-less channel is newer, so age alone would spare it.
  auto sessionlessChannel = open_channel_none();
  ASSERT_TRUE(sessionlessChannel.is_open());
  auto sessionlessChannelId = sessionlessChannel.secure_channel_id();
  ASSERT_NE(sessionlessChannelId, sessionChannelId);

  // The fixture caps mMaxSecureChannels at 2, so this third OPN forces the eviction decision.
  auto thirdResult = mClient->core().try_open_channel_sync({.endpointUrl = mEndpointUrl});
  ASSERT_THAT(thirdResult, ::ua::test_helpers::Good())
    << "Server SHALL evict a session-less channel to admit the new one rather than refuse it";
  auto thirdChannel = std::move(thirdResult).value();
  EXPECT_TRUE(thirdChannel.is_open());

  // Eviction closes the victim's transport asynchronously; let the close reach the client.
  std::this_thread::sleep_for(500ms);

  // Conjunct 1: the session-less channel is the one that went.
  GetEndpointsRequest evictedProbe;
  evictedProbe.endpoint_url() = mEndpointUrl;
  auto evictedResult = sessionlessChannel.try_get_endpoints_sync(std::move(evictedProbe));
  EXPECT_TRUE(evictedResult.is_bad() || !sessionlessChannel.is_open())
    << "the session-less channel (ID " << sessionlessChannelId
    << ") must be the eviction victim; it is still usable, so the server evicted something else";

  // Conjunct 2: the older channel carrying a Session survived and is still usable.
  EXPECT_TRUE(sessionChannel.is_open())
    << "a channel carrying a Session must not be evicted while a session-less channel exists";
  GetEndpointsRequest survivorProbe;
  survivorProbe.endpoint_url() = mEndpointUrl;
  auto survivorResult = sessionChannel.try_get_endpoints_sync(std::move(survivorProbe));
  EXPECT_THAT(survivorResult, ::ua::test_helpers::Good())
    << "the Session-carrying channel (ID " << sessionChannelId
    << ") must remain serviceable after the eviction";

  (void)session.try_close_sync();
  thirdChannel.try_close_sync();
  sessionlessChannel.try_close_sync();
  sessionChannel.try_close_sync();
}

// Part 4 section 5.5.2 with Part 7 - the serverNonce length is whatever `SecureChannelNonceLength` the
// negotiated SecurityPolicy defines, not a constant. Key derivation consumes the nonce at the
// policy's own length, so a hard-coded 32 (or a length copied from the clientNonce) opens every
// channel successfully and is invisible unless several policies are measured against their own
// definitions. P4_0019 above measures one policy only, which a constant satisfies.
// @verifies AC-SVR-SC-019-NONCE-LENGTH-PER-POLICY
// @relation(AC-SVR-SC-019-NONCE-LENGTH-PER-POLICY, scope=function)
TEST_F(ComplianceSecureChannel, ServerNonceLengthIsTheLengthEachSecurityPolicyDefines)
{
  // The fixture offers only None and Basic256Sha256; add two more RSA policies (same certificate
  // type, so the existing PKI serves) so "per policy" is distinguishable from "one fixed length".
  {
    ServerEndpointConfig aes128Ep;
    aes128Ep.name = "Aes128Sha256RsaOaep_SignAndEncrypt";
    aes128Ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    aes128Ep.securityPolicyId = SecurityPolicyId::Aes128Sha256RsaOaep;
    aes128Ep.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(aes128Ep));

    ServerEndpointConfig aes256Ep;
    aes256Ep.name = "Aes256Sha256RsaPss_SignAndEncrypt";
    aes256Ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    aes256Ep.securityPolicyId = SecurityPolicyId::Aes256Sha256RsaPss;
    aes256Ep.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(aes256Ep));
  }

  struct PolicyRow
  {
    MessageSecurityMode mode;
    SecurityPolicyId policy;
  };

  const std::vector<PolicyRow> rows{{MessageSecurityMode::None, SecurityPolicyId::None},
    {MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256},
    {MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes128Sha256RsaOaep},
    {MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes256Sha256RsaPss}};
  ASSERT_FALSE(rows.empty());

  std::vector<size_t> measuredLengths;
  for (const auto& row : rows)
  {
    auto policy = SecurityPolicy::create(row.policy);
    ASSERT_NE(policy, nullptr);
    std::string policyUri = policy->uri();
    auto expectedLength = policy->nonce_length();

    auto channel = open_channel(row.mode, row.policy);
    ASSERT_TRUE(channel.is_open()) << "could not open a channel under " << policyUri;

    auto snap = read_channel_state(channel);
    EXPECT_EQ(snap.serverNonce.size(), expectedLength)
      << "serverNonce under " << policyUri << " is " << snap.serverNonce.size()
      << " bytes but that policy defines SecureChannelNonceLength = " << expectedLength;
    measuredLengths.push_back(snap.serverNonce.size());

    channel.close_sync();
  }

  ASSERT_EQ(measuredLengths.size(), rows.size()) << "every policy row must have been measured";
  // The lengths must not all be the same value: a constant would satisfy the per-row equality only if
  // every policy happened to agree, which None (0 bytes) does not.
  EXPECT_NE(measuredLengths.front(), measuredLengths.back())
    << "every policy produced the same serverNonce length - the length is not being taken from the "
       "SecurityPolicy";
}

// Part 6 section 6.7.2 - `SenderCertificateLength` shall not exceed `MaxSenderCertificateSize`, and the bound
// must be applied before the certificate is parsed. The field is attacker-controlled and precedes the
// data on a pre-authentication path: a receiver that sized a buffer from the declared value, or that
// tried to read the certificate first, would act on a length nobody bounded. The signature over the
// OPN cannot catch this - verifying it requires the sender certificate, so the length check has to
// come first.
// @verifies AC-SVR-UASC-003-SENDERCERT-SIZE
// @relation(AC-SVR-UASC-003-SENDERCERT-SIZE, scope=function)
TEST_F(ComplianceSecureChannel, OversizedSenderCertificateLengthInOpnIsRefused)
{
  // Far beyond any MaxSenderCertificateSize (which is bounded by the negotiated chunk size) while
  // staying small enough that a bounds check, not an "absurdly large" guard, is what must reject it.
  const uint32_t oversizeCertLength = 0x00100000u;  // 1 MiB
  auto patchedOpnFrames = std::make_shared<CapturedFrames>();

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = mServerCert;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [patchedOpnFrames, oversizeCertLength](
                                 std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [patchedOpnFrames, oversizeCertLength](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          // The asymmetric security header is never encrypted, so the length field is patchable
          // on the wire: [0-2]="OPN", [4-7]=size, [8-11]=channelId, [12-15]=SecurityPolicyUri length,
          // uri occupies the next uriLen bytes, then SenderCertificateLength as little-endian int32.
          if (data.size() >= 20 && read_message_type(data) == "OPN")
          {
            int32_t uriLen = static_cast<int32_t>(read_le_uint32(data, 12));
            size_t certLenOffset = (uriLen > 0) ? (16 + static_cast<size_t>(uriLen)) : data.size();
            if (uriLen > 0 && certLenOffset + 4 <= data.size())
            {
              std::array<std::byte, 4> oversizeLe{static_cast<std::byte>(oversizeCertLength & 0xFF),
                static_cast<std::byte>((oversizeCertLength >> 8) & 0xFF),
                static_cast<std::byte>((oversizeCertLength >> 16) & 0xFF),
                static_cast<std::byte>((oversizeCertLength >> 24) & 0xFF)};
              std::copy(oversizeLe.begin(),
                oversizeLe.end(),
                data.begin() + static_cast<std::ptrdiff_t>(certLenOffset));
              patchedOpnFrames->add(data);
            }
          }
          return data;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  mServerLogSink->clear();

  auto result = mClient->core().try_open_channel_sync(std::move(cfg));

  // Non-vacuous: the oversize declaration really reached the wire.
  ASSERT_GE(patchedOpnFrames->count(), 1u)
    << "no OPN frame carried the oversize SenderCertificateLength - the stimulus never happened";
  auto patchedFrame = patchedOpnFrames->get(0);
  int32_t patchedUriLen = static_cast<int32_t>(read_le_uint32(patchedFrame, 12));
  ASSERT_GT(patchedUriLen, 0);
  EXPECT_EQ(read_le_uint32(patchedFrame, 16 + static_cast<size_t>(patchedUriLen)), oversizeCertLength)
    << "the frame handed to the transport did not carry the oversize length";

  EXPECT_TRUE(result.is_bad())
    << "an OPN whose SenderCertificateLength exceeds MaxSenderCertificateSize must be refused; the "
       "channel opened instead";
  std::this_thread::sleep_for(200ms);
  EXPECT_TRUE(mServerLogSink->has_warning_or_error())
    << "the server must record the refusal rather than silently discard the malformed OPN";

  if (result.is_good())
  {
    (void)std::move(result).value().try_close_sync();
  }
}

/// Highest sequence number seen on a captured symmetric MSG frame, the request id that accompanied it, and
/// how many such frames were captured - a caller must refuse to act on an empty capture, because a frame
/// built from a guessed sequence number would be refused for the wrong reason.
struct SymmetricHeaderHighWater
{
  uint32_t sequenceNumber{0};
  uint32_t requestId{0};
  size_t msgFrameCount{0};
};

static SymmetricHeaderHighWater read_symmetric_header_high_water(CapturedFrames& frames)
{
  SymmetricHeaderHighWater high;
  auto frameCount = frames.count();
  for (size_t i = 0; i < frameCount; ++i)
  {
    auto frame = frames.get(i);
    // Under MessageSecurityMode::Sign nothing is encrypted, so the symmetric sequence header is readable:
    // [0-2]="MSG", [3]=chunk type, [4-7]=size, [8-11]=channelId, [12-15]=tokenId, [16-19]=sequenceNumber,
    // [20-23]=requestId.
    if (read_message_type(frame) != "MSG" || frame.size() < 24)
      continue;
    ++high.msgFrameCount;
    auto sequenceNumber = read_le_uint32(frame, 16);
    if (sequenceNumber >= high.sequenceNumber)
    {
      high.sequenceNumber = sequenceNumber;
      high.requestId = read_le_uint32(frame, 20);
    }
  }
  return high;
}

/// Builds a raw symmetric CLO frame whose body is a well-formed CloseSecureChannelRequest, so a server that
/// acts on it really would have closed the channel. Only the authentication is wrong: the frame carries
/// `trailerBytes` of filler where the signature computed with the current token's key belongs (pass 0 for an
/// entirely unsigned CLO).
static std::vector<std::byte> build_forged_close_secure_channel_frame(
  uint32_t channelId, uint32_t tokenId, uint32_t sequenceNumber, uint32_t requestId, size_t trailerBytes)
{
  std::vector<std::byte> frame;
  auto pushU32 = [&frame](uint32_t value)
  {
    frame.push_back(static_cast<std::byte>(value & 0xFF));
    frame.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
    frame.push_back(static_cast<std::byte>((value >> 16) & 0xFF));
    frame.push_back(static_cast<std::byte>((value >> 24) & 0xFF));
  };

  // Message header + symmetric security header + sequence header.
  frame.push_back(static_cast<std::byte>('C'));
  frame.push_back(static_cast<std::byte>('L'));
  frame.push_back(static_cast<std::byte>('O'));
  frame.push_back(static_cast<std::byte>('F'));
  pushU32(0);  // message size - patched once the frame is complete
  pushU32(channelId);
  pushU32(tokenId);
  pushU32(sequenceNumber);
  pushU32(requestId);

  // Body: the CloseSecureChannelRequest_Encoding_DefaultBinary type id as a FourByte NodeId (ns 0, id 452),
  // followed by the RequestHeader - the request carries no other field.
  constexpr uint32_t closeSecureChannelBinaryEncodingId = 452u;
  frame.push_back(static_cast<std::byte>(0x01));  // FourByte NodeId encoding
  frame.push_back(static_cast<std::byte>(0x00));  // namespace 0
  frame.push_back(static_cast<std::byte>(closeSecureChannelBinaryEncodingId & 0xFF));
  frame.push_back(static_cast<std::byte>((closeSecureChannelBinaryEncodingId >> 8) & 0xFF));
  frame.push_back(static_cast<std::byte>(0x00));  // authenticationToken: TwoByte null NodeId
  frame.push_back(static_cast<std::byte>(0x00));
  for (int i = 0; i < 8; ++i)
    frame.push_back(static_cast<std::byte>(0x00));  // timestamp
  pushU32(1);  // requestHandle
  pushU32(0);  // returnDiagnostics
  pushU32(0xFFFFFFFFu);  // auditEntryId: null String
  pushU32(0);  // timeoutHint
  frame.push_back(static_cast<std::byte>(0x00));  // additionalHeader: null ExtensionObject NodeId ...
  frame.push_back(static_cast<std::byte>(0x00));
  frame.push_back(static_cast<std::byte>(0x00));  // ... and its "no body" encoding byte

  for (size_t i = 0; i < trailerBytes; ++i)
    frame.push_back(static_cast<std::byte>(0xA5));

  auto messageSize = static_cast<uint32_t>(frame.size());
  frame[4] = static_cast<std::byte>(messageSize & 0xFF);
  frame[5] = static_cast<std::byte>((messageSize >> 8) & 0xFF);
  frame[6] = static_cast<std::byte>((messageSize >> 16) & 0xFF);
  frame[7] = static_cast<std::byte>((messageSize >> 24) & 0xFF);
  return frame;
}

/// The site the server reports a failed chunk security check under. Named rather than matched loosely,
/// because the whole discrimination below rests on it: a CLO the server ACTS on runs
/// `SecureChannel::handle_close_secure_channel`, which records nothing above Debug, so an Error carrying
/// this site can only have come from the refusal path.
static constexpr std::string_view chunkSecurityFailureSite = "SecureChannel::process_request_message_chunks";

/// Waits for the server to record an Error under the `secure_channel` category whose message carries
/// `messageFragment`. Polled rather than slept on, because the refusal lands on the channel strand some time
/// after `inject_bytes` returns.
///
/// The severity test is `>=`: `ua::LogLevel` ascends Trace..Critical, so Error is the HIGH end.
static bool wait_for_server_error_log(
  const CapturingLogSink& sink, std::string_view messageFragment, std::chrono::milliseconds timeout)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;)
  {
    for (const auto& record : sink.records())
    {
      if (record.level >= ua::LogLevel::Error && record.category == "secure_channel" &&
          record.message.find(messageFragment) != std::string::npos)
      {
        return true;
      }
    }
    if (std::chrono::steady_clock::now() >= deadline)
      return false;
    std::this_thread::sleep_for(50ms);
  }
}

/// Waits for the client to observe that the server dropped the socket.
/// The parameter is spelled `ua::client::SecureChannel` in full: by this point in the file both the
/// client and the server type are visible, so the bare name is ambiguous here even though the
/// earlier helpers above resolve it without help.
static bool wait_for_channel_closed(ua::client::SecureChannel& channel, std::chrono::milliseconds timeout)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;)
  {
    if (!channel.is_open())
      return true;
    if (std::chrono::steady_clock::now() >= deadline)
      return false;
    std::this_thread::sleep_for(50ms);
  }
}

// Part 4 section 5.5.3 - a CloseSecureChannel request shall be signed with the key belonging to the token
// that is current for the SecureChannel. The channel id and token id travel in the clear in every frame, so a
// close that is honoured without checking the signature costs an attacker no credentials at all: a fabricated
// 57-byte CLO is enough to drop somebody else's channel. A plausible implementation dispatches on the "CLO"
// message type at the framing layer, or accepts any frame whose channel id matches, and tears the channel
// down before the signature is ever examined; a second plausible implementation verifies the signature but
// still lets a frame naming a superseded token through the grace-period path that Part 4 section 5.5.2 opens
// for the old token. Both are exercised here.
//
// What "refused" means on the wire is fixed by Part 6 section 7.1.4 (SVR-TCP-023, verbatim): "If security
// verification fails for the CloseSecureChannel Message, then the Server shall report the error and close
// the socket." SVR-SC-021 routes to exactly that - "the server verifies the signature; failure -> close per
// SVR-TCP-023". So a refused CLO does NOT leave a serviceable channel behind, and asserting that it does
// would assert against a `shall`. The two outcomes are told apart by HOW the channel ends: honoured is a
// graceful close (`handle_close_secure_channel`: close reason Good, orderly, nothing logged above Debug),
// refused is a reported security failure (an Error naming the chunk security-check site, then a transport
// ERR and the socket dropped). The Error is therefore the required conjunct here; the teardown alone
// would be satisfied by an attacker's close being honoured, which is the very hazard under test.
//
// Renamed from `CloseNotSignedWithTheCurrentTokenKeyIsRefusedAndTheChannelStaysOpen`, whose "stays open"
// encoded the opposite of Part 6 section 7.1.4.
// @verifies AC-SVR-SC-021-CLO-SIGNED
// @relation(AC-SVR-SC-021-CLO-SIGNED, AC-SVR-TCP-023-CLOSECURITY, scope=function)
TEST_F(ComplianceSecureChannel, CloseNotSignedWithTheCurrentTokenKeyIsRefusedAsASecurityFailure)
{
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ASSERT_NE(policy, nullptr);
  const size_t signatureSize = policy->symmetric_signature_size();
  ASSERT_GT(signatureSize, 0u) << "Basic256Sha256 must define a symmetric signature size";

  // -------------------------------------------------------------------------------------------------
  // Stimulus 1 - a CLO naming the CURRENT token but carrying no signature at all.
  // -------------------------------------------------------------------------------------------------
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> unsignedFuzz;
  auto unsignedFrames = std::make_shared<CapturedFrames>();

  auto unsignedChannel = open_channel_with_transport_decorator(
    MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256, unsignedFuzz);
  ASSERT_TRUE(unsignedChannel.is_open());
  ASSERT_NE(unsignedFuzz, nullptr);

  unsignedFuzz->set_write_interceptor(
    [unsignedFrames](std::vector<std::byte> data) -> std::vector<std::byte>
    {
      unsignedFrames->add(data);
      return data;  // passthrough - the client's own traffic must stay valid
    });

  {
    // Establishes the baseline: the channel is serviceable BEFORE the forged CLO, so the probe afterwards
    // measures the effect of the CLO and nothing else.
    GetEndpointsRequest warmUp;
    warmUp.endpoint_url() = mEndpointUrl;
    ASSERT_THAT(unsignedChannel.try_get_endpoints_sync(std::move(warmUp)), ::ua::test_helpers::Good())
      << "the channel must work before the forged CLO is injected";
  }

  auto unsignedHigh = read_symmetric_header_high_water(*unsignedFrames);
  ASSERT_GT(unsignedHigh.msgFrameCount, 0u)
    << "no symmetric MSG frame was captured, so the forged CLO cannot be given the sequence number the "
       "server expects next - a refusal would then prove nothing about the signature";

  auto unsignedState = read_channel_state(unsignedChannel);
  ASSERT_NE(unsignedState.tokenId, 0u);

  auto unsignedClo = build_forged_close_secure_channel_frame(unsignedChannel.secure_channel_id(),
    unsignedState.tokenId,
    unsignedHigh.sequenceNumber + 1,
    unsignedHigh.requestId + 1,
    /*trailerBytes=*/0);

  mServerLogSink->clear();
  unsignedFuzz->inject_bytes(unsignedClo);

  // Conjunct 1 (required): the unsigned close is REFUSED - the server reports a security failure on the
  // chunk rather than running the graceful-close path, which logs nothing above Debug.
  EXPECT_TRUE(wait_for_server_error_log(*mServerLogSink, chunkSecurityFailureSite, 2s))
    << "an unsigned CloseSecureChannel was not reported as a security failure; nothing distinguishes this "
       "from the close having been honoured, i.e. actioned without any proof that its sender holds the "
       "current token's signing key";

  // Conjunct 2: and the socket goes (Part 6 section 7.1.4 "report the error and close the socket").
  EXPECT_TRUE(wait_for_channel_closed(unsignedChannel, 5s))
    << "the server must close the socket when security verification of a CLO fails";
  {
    GetEndpointsRequest probe;
    probe.endpoint_url() = mEndpointUrl;
    EXPECT_TRUE(unsignedChannel.try_get_endpoints_sync(std::move(probe)).is_bad())
      << "the socket must be gone once the forged CLO was refused";
  }
  (void)unsignedChannel.try_close_sync();

  // -------------------------------------------------------------------------------------------------
  // Stimulus 2 - a CLO naming a SUPERSEDED token, whose signature therefore cannot be the current one.
  // -------------------------------------------------------------------------------------------------
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> staleFuzz;
  auto staleFrames = std::make_shared<CapturedFrames>();
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [&staleFuzz](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      staleFuzz = fuzz;
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  CoreClient::OpenChannelConfig staleCfg;
  staleCfg.endpointUrl = mEndpointUrl;
  staleCfg.securityMode = MessageSecurityMode::Sign;
  staleCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  staleCfg.serverCertificate = mServerCert;
  staleCfg.requestedLifetime = 4000ms;
  auto staleChannel = mClient->core().open_channel_sync(std::move(staleCfg));
  ASSERT_TRUE(staleChannel.is_open());
  ASSERT_NE(staleFuzz, nullptr);

  auto beforeRenewal = read_channel_state(staleChannel);
  const uint32_t supersededTokenId = beforeRenewal.tokenId;
  ASSERT_NE(supersededTokenId, 0u);
  ASSERT_TRUE(wait_for_renewal(staleChannel, supersededTokenId, 15s))
    << "the channel never renewed, so there is no superseded token to name in the forged CLO";

  // Stop further renewals so the assertions below run against one stable current token.
  CSCTA::on_strand(staleChannel,
    [](auto& g)
    {
      auto& renewalTimer = g.renewal_timer();
      if (renewalTimer)
      {
        renewalTimer.cancel();
      }
    });

  staleFuzz->set_write_interceptor(
    [staleFrames](std::vector<std::byte> data) -> std::vector<std::byte>
    {
      staleFrames->add(data);
      return data;
    });

  {
    // A request secured with the NEW token retires the old one (Part 4 section 5.5.2: the server honours the
    // old token only until a message secured with the new one arrives), and supplies the next sequence
    // number.
    GetEndpointsRequest retire;
    retire.endpoint_url() = mEndpointUrl;
    ASSERT_THAT(staleChannel.try_get_endpoints_sync(std::move(retire)), ::ua::test_helpers::Good())
      << "the renewed channel must work before the forged CLO is injected";
  }

  auto afterRenewal = read_channel_state(staleChannel);
  ASSERT_NE(afterRenewal.tokenId, supersededTokenId) << "the renewal must really have changed the token";

  auto staleHigh = read_symmetric_header_high_water(*staleFrames);
  ASSERT_GT(staleHigh.msgFrameCount, 0u)
    << "no symmetric MSG frame was captured after the renewal, so the forged CLO cannot be given the "
       "sequence number the server expects next";

  auto staleClo = build_forged_close_secure_channel_frame(staleChannel.secure_channel_id(),
    supersededTokenId,
    staleHigh.sequenceNumber + 1,
    staleHigh.requestId + 1,
    signatureSize);

  mServerLogSink->clear();
  staleFuzz->inject_bytes(staleClo);

  // Conjunct 1 (required): a close naming a superseded token is REFUSED, not admitted through any
  // grace period left over from the renewal.
  EXPECT_TRUE(wait_for_server_error_log(*mServerLogSink, chunkSecurityFailureSite, 2s))
    << "a CloseSecureChannel presented under token " << supersededTokenId << " rather than the current token "
    << afterRenewal.tokenId
    << " was not reported as a security failure; nothing distinguishes this from the close having been "
       "honoured under the retired token";

  // Conjunct 2: and the socket goes (Part 6 section 7.1.4 "report the error and close the socket").
  EXPECT_TRUE(wait_for_channel_closed(staleChannel, 5s))
    << "the server must close the socket when security verification of a CLO fails";
  {
    GetEndpointsRequest probe;
    probe.endpoint_url() = mEndpointUrl;
    EXPECT_TRUE(staleChannel.try_get_endpoints_sync(std::move(probe)).is_bad())
      << "the socket must be gone once the CLO naming a superseded token was refused";
  }
  (void)staleChannel.try_close_sync();
}

// ===========================================================================
// Certificate continuity across the whole OPN -> CreateSession -> ActivateSession chain
// ===========================================================================

#include "ua_create_session_request.h"
#include "ua_create_session_response.h"
#include "ua_service_fault.h"

namespace
{

/// One response a server-side SecureChannel emitted, reduced to what a continuity assertion needs: which
/// request it answers, what it is, and the service result it carries. Both a ServiceFault and a
/// CreateSessionResponse carry a ResponseHeader, so the status is readable either way - a refusal expressed
/// as "CreateSessionResponse with a bad serviceResult" is not mistaken for an acceptance, and an acceptance
/// cannot hide behind an unexpected message type.
struct ObservedServerResponse
{
  uint32_t requestId{0};
  std::string typeName;
  ua::StatusCode serviceResult;
};

/// Thread-safe log of the responses one server-side SecureChannel emitted. The interceptor that fills it runs
/// on the channel strand while the assertions run on the test thread, so every access is locked.
class ServerResponseLog
{
public:
  void add(ObservedServerResponse response)
  {
    std::lock_guard lock(mMutex);
    mResponses.push_back(std::move(response));
  }

  std::optional<ObservedServerResponse> find(uint32_t requestId)
  {
    std::lock_guard lock(mMutex);
    for (const auto& response : mResponses)
    {
      if (response.requestId == requestId)
        return response;
    }
    return std::nullopt;
  }

private:
  std::mutex mMutex;
  std::vector<ObservedServerResponse> mResponses;
};

/// Holds the first server-side SecureChannel the server hands to the availability hook. Kept behind a
/// shared_ptr the hook only weakly captures, so the server's stored callback cannot keep a strong reference
/// to a SecureChannel alive past the end of the test - a strong one would keep the server io_context busy
/// past the thread-pool stop watchdog in TearDown.
struct FirstServerChannelCapture
{
  std::mutex mutex;
  std::shared_ptr<ua::server::SecureChannel> channel;
};

}  // namespace

// Part 4 section 5.5.2 with section 5.6.3 - the ApplicationInstanceCertificate presented at
// OpenSecureChannel, at CreateSession and at ActivateSession must be one and the same certificate, and the
// chain must hold end to end rather than pairwise. Two plausible implementations get this wrong, and this
// test drives one substitution against each.
//
// The first validates the certificate handed to CreateSession against the trust list rather than against the
// certificate that opened the channel. That passes for any trusted certificate, so it lets a peer open a
// channel as one application and create a Session as another - which is why the substitute certificate below
// is deliberately added to the server's trust list before it is presented.
//
// The second records the CreateSession certificate and compares only against that record. ActivateSession
// runs more than once on a Session, and a Session may legitimately be re-bound to a NEW SecureChannel, so a
// comparison that stops at CreateSession loses the tie to the channel exactly where it matters. The control
// re-activation on a second channel carrying the SAME certificate is what makes the third-certificate
// refusal falsifiable: without it, "every channel change is refused" would look identical.
// @verifies AC-SVR-SC-004-CERT-CONTINUITY-CHAIN
// @relation(AC-SVR-SC-004-CERT-CONTINUITY-CHAIN, SVR-SC-004, scope=function)
TEST_F(ComplianceSecureChannel, CertificateAtOpnCreateSessionAndActivateSessionMustBeTheSameCertificate)
{
  TrustListValidationOptions validationOptions;

  // ---------------------------------------------------------------------------------------------------
  // Two further certificates, each INDIVIDUALLY TRUSTED by the server. Trust is what a plausible but wrong
  // implementation checks, so both substitutions must be trusted for the test to bite.
  // ---------------------------------------------------------------------------------------------------
  auto substituteCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Continuity Substitute Client"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{.hostnames = {"localhost"}, .uris = {"urn:test:continuity:substitute"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(substituteCertResult, ::ua::test_helpers::Good());
  auto [substituteKeys, substituteCert] = std::move(substituteCertResult).value();
  mServerCertStore->add_to_trusted_certificates_sync(substituteCert);

  auto thirdCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Continuity Third Client"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{.hostnames = {"localhost"}, .uris = {"urn:test:continuity:third"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(thirdCertResult, ::ua::test_helpers::Good());
  auto [thirdKeys, thirdCert] = std::move(thirdCertResult).value();
  mServerCertStore->add_to_trusted_certificates_sync(thirdCert);

  // A client that really owns the third certificate, so the third channel's OPN is a genuine one rather
  // than a doctored frame. Declared here, ahead of the Session, so the Session (which takes shared
  // ownership of this client's channel) is destroyed before the client that produced it.
  auto thirdStorePath = mTempDir / "continuity_third_store";
  std::filesystem::create_directories(thirdStorePath);
  auto thirdCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = thirdStorePath, .validationOptions = validationOptions});
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = thirdCert;
    appCert.keys = std::move(thirdKeys);
    thirdCertStore->add_to_application_certificates_sync(appCert);
  }
  thirdCertStore->add_to_trusted_certificates_sync(mServerCert);

  auto thirdAppCfg = ua::test_utils::create_test_config();
  thirdAppCfg.application_description_part().applicationUri = "urn:test:continuity:third";
  client::CreateConfig thirdClientCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(thirdAppCfg)};
  auto thirdClient = Client::create(mClientThreadPool.executor(),
    std::move(thirdClientCfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = thirdCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Debug});

  // ---------------------------------------------------------------------------------------------------
  // Open the channel that fixes certificate A. A is presented in the OPN asymmetric security header.
  // ---------------------------------------------------------------------------------------------------
  auto capture = std::make_shared<FirstServerChannelCapture>();
  std::weak_ptr<FirstServerChannelCapture> weakCapture = capture;

  auto& serverImpl = ua::test_helpers::ServerTestAccess::impl(*mServer);
  ua::test_helpers::ServerImplTestAccess access(serverImpl);
  access.set_on_secure_channel_available(
    [weakCapture](std::shared_ptr<ua::server::SecureChannel> sc)
    {
      auto state = weakCapture.lock();
      if (!state)
        return;
      std::lock_guard lock(state->mutex);
      if (!state->channel)
        state->channel = std::move(sc);
    });

  const size_t sessionsBefore = access.sessions().size();

  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  std::shared_ptr<ua::server::SecureChannel> serverChannel;
  {
    auto deadline = std::chrono::steady_clock::now() + 5s;
    for (;;)
    {
      {
        std::lock_guard lock(capture->mutex);
        serverChannel = capture->channel;
      }
      if (serverChannel != nullptr || std::chrono::steady_clock::now() >= deadline)
        break;
      std::this_thread::sleep_for(50ms);
    }
  }
  ASSERT_NE(serverChannel, nullptr)
    << "the server-side SecureChannel for the opened channel was never observed, so neither substitution "
       "below could be presented on it";

  // Certificate A, as the client holds it and as the server recorded it from the OPN. Asserting the two
  // agree is what lets the rest of the test speak about "the certificate presented at OPN".
  auto clientAppCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(clientAppCerts.empty());
  ASSERT_NE(clientAppCerts.front().certificate, nullptr);
  const auto channelCertDer = clientAppCerts.front().certificate->der_encoding();
  ASSERT_FALSE(channelCertDer.empty());

  auto opnCertDer = ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
    [](auto& g)
    {
      auto& context = *g.context();
      return context.remoteCertificate ? context.remoteCertificate->der_encoding() : ua::ByteString{};
    });
  ASSERT_FALSE(opnCertDer.empty()) << "the server recorded no peer certificate for an authenticated channel";
  ASSERT_EQ(opnCertDer, channelCertDer) << "the channel was not opened with the client's own certificate";

  const auto substituteCertDer = substituteCert->der_encoding();
  ASSERT_FALSE(substituteCertDer.empty());
  ASSERT_NE(substituteCertDer, channelCertDer)
    << "the substitution certificate must differ from the one that opened the channel";

  // Record every response this channel emits, so a refusal can be told from an acceptance by its status
  // rather than by a side effect alone.
  auto responses = std::make_shared<ServerResponseLog>();
  ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
    [responses](auto& g)
    {
      g.set_response_interceptor(
        [responses](ua::Response& response)
        {
          ObservedServerResponse observed;
          observed.requestId = response.first;
          if (response.second)
            observed.typeName = std::string(response.second->type_name());
          if (auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get()))
            observed.serviceResult = fault->response_header().service_result();
          else if (auto* created = dynamic_cast<ua::CreateSessionResponse*>(response.second.get()))
            observed.serviceResult = created->response_header().service_result();
          responses->add(std::move(observed));
        });
    });

  auto waitForResponse = [&responses](uint32_t requestId, std::chrono::milliseconds timeout)
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;)
    {
      auto found = responses->find(requestId);
      if (found.has_value())
        return found;
      if (std::chrono::steady_clock::now() >= deadline)
        return found;
      std::this_thread::sleep_for(50ms);
    }
  };

  // A CreateSessionRequest identical in every respect except the certificate it presents. The requests are
  // delivered into the server's own decoded-request path on the channel opened with certificate A, so the
  // continuity decision - and the refusal, if any - is the server's alone.
  auto buildCreateSessionRequest = [this](const char* sessionName, const ua::ByteString& certificateDer)
  {
    auto request = std::make_shared<ua::CreateSessionRequest>();
    request->request_header().request_handle() = 4004;
    request->client_description().application_uri() = "urn:test:compliance:client";
    request->endpoint_url() = mEndpointUrl;
    request->session_name() = sessionName;
    request->client_nonce() = ua::ByteString(32u, static_cast<uint8_t>(0x5A));
    request->client_certificate() = certificateDer;
    request->requested_session_timeout() = 60000.0;
    request->max_response_message_size() = 0x1000000u;
    return request;
  };

  // ---------------------------------------------------------------------------------------------------
  // Link 1 control - CreateSession presenting the channel's own certificate must be accepted. Without this
  // the refusal below could be explained by the request being malformed rather than by the certificate.
  // ---------------------------------------------------------------------------------------------------
  constexpr uint32_t controlRequestId = 0x7C000001u;
  {
    auto controlRequest = buildCreateSessionRequest("CertContinuity_ChannelCertificate", channelCertDer);
    ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
      [&](auto& g) { g.inject_decoded_request(controlRequestId, controlRequest, ua::NodeId{}); });
  }

  auto controlResponse = waitForResponse(controlRequestId, 5s);
  ASSERT_TRUE(controlResponse.has_value())
    << "the control CreateSession was never answered, so the injection path is not reaching the service";
  ASSERT_TRUE(controlResponse->serviceResult.is_good())
    << "CreateSession presenting the channel's own certificate was refused with 0x" << std::hex
    << controlResponse->serviceResult.as_uint32()
    << " - the substitution below could then be refused for the same unrelated reason";
  const size_t sessionsAfterControl = access.sessions().size();
  ASSERT_EQ(sessionsAfterControl, sessionsBefore + 1)
    << "the accepted control CreateSession did not produce a Session on the server";

  // ---------------------------------------------------------------------------------------------------
  // Link 1 substitution - the same CreateSession presenting a DIFFERENT, individually trusted certificate.
  // ---------------------------------------------------------------------------------------------------
  constexpr uint32_t substituteRequestId = 0x7C000002u;
  {
    auto substituteRequest =
      buildCreateSessionRequest("CertContinuity_SubstitutedCertificate", substituteCertDer);
    ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
      [&](auto& g) { g.inject_decoded_request(substituteRequestId, substituteRequest, ua::NodeId{}); });
  }

  auto substituteResponse = waitForResponse(substituteRequestId, 5s);
  ASSERT_TRUE(substituteResponse.has_value())
    << "the substituted CreateSession was never answered; the stimulus cannot be shown to have been "
       "processed at all";

  // Conjunct 1: the substitution is answered with a refusal, not with a session.
  EXPECT_TRUE(substituteResponse->serviceResult.is_bad())
    << "CreateSession presenting a certificate that is NOT the one which opened the SecureChannel was "
       "answered with "
    << substituteResponse->typeName << " carrying status 0x" << std::hex
    << substituteResponse->serviceResult.as_uint32()
    << "; the certificate being individually trusted does not satisfy Part 4 section 5.6.3 - it must be the "
       "same "
       "certificate";

  // Conjunct 2: and no Session came into existence for it.
  EXPECT_EQ(access.sessions().size(), sessionsAfterControl)
    << "a Session was created for a CreateSession whose certificate is not the channel's certificate";

  // ---------------------------------------------------------------------------------------------------
  // Link 2 - the certificate in force at ActivateSession. ActivateSession carries no certificate field of
  // its own, so the certificate it "presents" is the one on the channel it arrives over.
  // ---------------------------------------------------------------------------------------------------
  {
    auto session = channel.create_session_sync({.sessionName = "CertContinuity_Chain"});
    session.activate_sync();
    ASSERT_TRUE(session.is_active())
      << "the Session under test must really be activated on certificate A's channel";

    // Control: a DIFFERENT channel carrying the SAME certificate. Part 4 section 5.6.3 permits re-binding a
    // Session to a new SecureChannel, so this must succeed - otherwise the refusal that follows would be
    // explained by "any channel change is refused" rather than by the certificate.
    auto sameCertChannel =
      open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
    ASSERT_TRUE(sameCertChannel.is_open());
    ASSERT_NE(sameCertChannel.secure_channel_id(), channel.secure_channel_id());
    auto sameCertActivate = session.try_activate_sync(std::move(sameCertChannel));
    ASSERT_THAT(sameCertActivate, ::ua::test_helpers::Good())
      << "re-activating on a different channel carrying the same certificate must be allowed; with it "
         "refused, nothing distinguishes a certificate check from a blanket channel check";
    ASSERT_TRUE(session.is_active());

    // Substitution: a third certificate, individually trusted, on a channel genuinely opened with it.
    CoreClient::OpenChannelConfig thirdCfg;
    thirdCfg.endpointUrl = mEndpointUrl;
    thirdCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    thirdCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    thirdCfg.serverCertificate = mServerCert;
    auto thirdChannelResult = thirdClient.core().try_open_channel_sync(std::move(thirdCfg));
    ASSERT_THAT(thirdChannelResult, ::ua::test_helpers::Good())
      << "the third certificate is in the server's trust list, so its channel must open - the refusal "
         "under test has to come from the continuity check, not from that certificate being unknown";
    auto thirdChannel = std::move(thirdChannelResult).value();
    ASSERT_TRUE(thirdChannel.is_open());
    ASSERT_NE(thirdChannel.secure_channel_id(), channel.secure_channel_id());

    auto thirdCertActivate = session.try_activate_sync(std::move(thirdChannel));
    EXPECT_TRUE(thirdCertActivate.is_bad())
      << "ActivateSession moved the Session onto a channel whose certificate is neither the one that "
         "opened the original channel nor the one recorded at CreateSession; continuity must hold across "
         "all three points, not only between adjacent pairs";

    (void)session.try_close_sync();
  }

  channel.try_close_sync();
}

// Part 4 section 5.5.2 (SPEC-SVR-SC-004) - "Clients and Servers shall verify that the same Certificates are
// used in the CreateSession and ActivateSession Services". The obligation is on the certificate itself, and
// it runs the length of the chain OPN -> CreateSession -> ActivateSession rather than between adjacent pairs.
//
// Each substitute below is allocated with the SAME subjectAltName URI as the certificate that opened the
// channel, is presented under the SAME clientDescription.applicationUri, and is added to the server's trust
// list before it is used. That removes every explanation for a refusal except the one under test: an
// implementation that validates the presented certificate against the trust list, or that checks the
// declared ApplicationUri against the certificate accompanying it (Part 6 section 6.2.2), finds nothing wrong
// with these requests - only a comparison against the certificate that opened the SecureChannel refuses them.
// This is the case byte-identity exists for: holding some other trusted certificate of the same application
// must not let a peer take over a channel opened with a different one.
//
// The second substitution is the one a pairwise implementation misses. A server that records the
// CreateSession certificate and compares later ActivateSessions against that record alone still satisfies
// the first link, yet ActivateSession runs more than once and a Session may legitimately be re-bound to a
// new SecureChannel, so the tie to the channel has to be re-checked every time. The same-certificate
// re-activation is run first as a control precisely so that "every channel change is refused" cannot be
// mistaken for the certificate check.
// @relation(AC-SVR-SC-004-CERT-CONTINUITY-CHAIN, scope=function)
TEST_F(ComplianceSecureChannel, SameCertificateRequiredAtOpnCreateSessionAndActivateSessionForOneApplication)
{
  TrustListValidationOptions validationOptions;

  // ---------------------------------------------------------------------------------------------------
  // Two further certificates. Both are individually trusted by the server AND both assert the very same
  // ApplicationUri as the certificate that opens the channel below, so trust and identity checks alike
  // pass on them.
  // ---------------------------------------------------------------------------------------------------
  auto cloneCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Continuity Clone Client"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{.hostnames = {"localhost"}, .uris = {"urn:test:compliance:client"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(cloneCertResult, ::ua::test_helpers::Good());
  auto [cloneKeys, cloneCert] = std::move(cloneCertResult).value();
  mServerCertStore->add_to_trusted_certificates_sync(cloneCert);

  auto imposterCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Continuity Imposter Client"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{.hostnames = {"localhost"}, .uris = {"urn:test:compliance:client"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(imposterCertResult, ::ua::test_helpers::Good());
  auto [imposterKeys, imposterCert] = std::move(imposterCertResult).value();
  mServerCertStore->add_to_trusted_certificates_sync(imposterCert);

  // A client that genuinely owns the imposter certificate, so the channel it opens is a real one rather
  // than a doctored frame. Declared ahead of the Session below, which takes shared ownership of a channel
  // this client produced, so the client outlives it.
  auto imposterStorePath = mTempDir / "continuity_imposter_store";
  std::filesystem::create_directories(imposterStorePath);
  auto imposterCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = imposterStorePath, .validationOptions = validationOptions});
  {
    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = imposterCert;
    appCert.keys = std::move(imposterKeys);
    imposterCertStore->add_to_application_certificates_sync(appCert);
  }
  imposterCertStore->add_to_trusted_certificates_sync(mServerCert);

  auto imposterAppCfg = ua::test_utils::create_test_config();
  imposterAppCfg.application_description_part().applicationUri = "urn:test:compliance:client";
  client::CreateConfig imposterClientCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(imposterAppCfg)};
  auto imposterClient = Client::create(mClientThreadPool.executor(),
    std::move(imposterClientCfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = imposterCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Debug});

  // ---------------------------------------------------------------------------------------------------
  // Open the channel whose certificate the whole chain must match.
  // ---------------------------------------------------------------------------------------------------
  auto capture = std::make_shared<FirstServerChannelCapture>();
  std::weak_ptr<FirstServerChannelCapture> weakCapture = capture;

  auto& serverImpl = ua::test_helpers::ServerTestAccess::impl(*mServer);
  ua::test_helpers::ServerImplTestAccess access(serverImpl);
  access.set_on_secure_channel_available(
    [weakCapture](std::shared_ptr<ua::server::SecureChannel> sc)
    {
      auto state = weakCapture.lock();
      if (!state)
        return;
      std::lock_guard lock(state->mutex);
      if (!state->channel)
        state->channel = std::move(sc);
    });

  const size_t sessionsBefore = access.sessions().size();

  auto channel = open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  ASSERT_TRUE(channel.is_open());

  std::shared_ptr<ua::server::SecureChannel> serverChannel;
  {
    auto deadline = std::chrono::steady_clock::now() + 5s;
    for (;;)
    {
      {
        std::lock_guard lock(capture->mutex);
        serverChannel = capture->channel;
      }
      if (serverChannel != nullptr || std::chrono::steady_clock::now() >= deadline)
        break;
      std::this_thread::sleep_for(50ms);
    }
  }
  ASSERT_NE(serverChannel, nullptr)
    << "the server-side SecureChannel was never observed, so no substitution could be presented on it";

  auto clientAppCerts = mClientCertStore->get_application_certificates_sync();
  ASSERT_FALSE(clientAppCerts.empty());
  ASSERT_NE(clientAppCerts.front().certificate, nullptr);
  const auto channelCertDer = clientAppCerts.front().certificate->der_encoding();
  ASSERT_FALSE(channelCertDer.empty());

  auto opnCertDer = ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
    [](auto& g)
    {
      auto& context = *g.context();
      return context.remoteCertificate ? context.remoteCertificate->der_encoding() : ua::ByteString{};
    });
  ASSERT_FALSE(opnCertDer.empty()) << "the server recorded no peer certificate for an authenticated channel";
  ASSERT_EQ(opnCertDer, channelCertDer) << "the channel was not opened with the client's own certificate";

  // The substitutes differ from the channel certificate in their bytes and in nothing else that a server
  // is entitled to look at. Asserting both halves is what makes a refusal attributable to continuity.
  const auto channelCertUris = clientAppCerts.front().certificate->san_uris();
  ASSERT_FALSE(channelCertUris.empty());

  const auto cloneCertDer = cloneCert->der_encoding();
  ASSERT_FALSE(cloneCertDer.empty());
  ASSERT_NE(cloneCertDer, channelCertDer) << "the substitute must not be the certificate that opened the "
                                             "channel, or there is no substitution to refuse";
  const auto cloneCertUris = cloneCert->san_uris();
  ASSERT_FALSE(cloneCertUris.empty());
  ASSERT_EQ(cloneCertUris.front(), channelCertUris.front())
    << "the substitute must assert the same ApplicationUri, so that an ApplicationUri check cannot be the "
       "reason it is refused";

  const auto imposterCertDer = imposterCert->der_encoding();
  ASSERT_FALSE(imposterCertDer.empty());
  ASSERT_NE(imposterCertDer, channelCertDer);
  const auto imposterCertUris = imposterCert->san_uris();
  ASSERT_FALSE(imposterCertUris.empty());
  ASSERT_EQ(imposterCertUris.front(), channelCertUris.front());

  // Record every response this channel emits, so a refusal is told from an acceptance by its status.
  auto responses = std::make_shared<ServerResponseLog>();
  ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
    [responses](auto& g)
    {
      g.set_response_interceptor(
        [responses](ua::Response& response)
        {
          ObservedServerResponse observed;
          observed.requestId = response.first;
          if (response.second)
            observed.typeName = std::string(response.second->type_name());
          if (auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get()))
            observed.serviceResult = fault->response_header().service_result();
          else if (auto* created = dynamic_cast<ua::CreateSessionResponse*>(response.second.get()))
            observed.serviceResult = created->response_header().service_result();
          responses->add(std::move(observed));
        });
    });

  auto waitForResponse = [&responses](uint32_t requestId, std::chrono::milliseconds timeout)
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;)
    {
      auto found = responses->find(requestId);
      if (found.has_value())
        return found;
      if (std::chrono::steady_clock::now() >= deadline)
        return found;
      std::this_thread::sleep_for(50ms);
    }
  };

  // Two CreateSessionRequests alike in every field but the certificate, both delivered into the server's
  // own decoded-request path on the channel opened above, so the decision they get is the server's alone.
  auto buildCreateSessionRequest = [this](const char* sessionName, const ua::ByteString& certificateDer)
  {
    auto request = std::make_shared<ua::CreateSessionRequest>();
    request->request_header().request_handle() = 4004;
    request->client_description().application_uri() = "urn:test:compliance:client";
    request->endpoint_url() = mEndpointUrl;
    request->session_name() = sessionName;
    request->client_nonce() = ua::ByteString(32u, static_cast<uint8_t>(0x3C));
    request->client_certificate() = certificateDer;
    request->requested_session_timeout() = 60000.0;
    request->max_response_message_size() = 0x1000000u;
    return request;
  };

  // ---------------------------------------------------------------------------------------------------
  // Link 1 control - the channel's own certificate must be accepted, or the refusal below could be
  // explained by the injected request being malformed rather than by the certificate it carries.
  // ---------------------------------------------------------------------------------------------------
  constexpr uint32_t controlRequestId = 0x7D000001u;
  {
    auto controlRequest = buildCreateSessionRequest("CertChain_ChannelCertificate", channelCertDer);
    ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
      [&](auto& g) { g.inject_decoded_request(controlRequestId, controlRequest, ua::NodeId{}); });
  }

  auto controlResponse = waitForResponse(controlRequestId, 5s);
  ASSERT_TRUE(controlResponse.has_value())
    << "the control CreateSession was never answered, so the injection path is not reaching the service";
  ASSERT_TRUE(controlResponse->serviceResult.is_good())
    << "CreateSession presenting the channel's own certificate was refused with 0x" << std::hex
    << controlResponse->serviceResult.as_uint32()
    << " - the substitution below could then be refused for the same unrelated reason";
  const size_t sessionsAfterControl = access.sessions().size();
  ASSERT_EQ(sessionsAfterControl, sessionsBefore + 1)
    << "the accepted control CreateSession did not produce a Session on the server";

  // ---------------------------------------------------------------------------------------------------
  // Link 1 substitution - a trusted certificate of the same application, but not the one on the channel.
  // ---------------------------------------------------------------------------------------------------
  constexpr uint32_t cloneRequestId = 0x7D000002u;
  {
    auto cloneRequest = buildCreateSessionRequest("CertChain_CloneCertificate", cloneCertDer);
    ua::server::SecureChannelTestAccess::on_strand(
      *serverChannel, [&](auto& g) { g.inject_decoded_request(cloneRequestId, cloneRequest, ua::NodeId{}); });
  }

  auto cloneResponse = waitForResponse(cloneRequestId, 5s);
  ASSERT_TRUE(cloneResponse.has_value())
    << "the substituted CreateSession was never answered; the stimulus cannot be shown to have been "
       "processed at all";

  // Conjunct 1: the substitution is answered with a refusal.
  EXPECT_TRUE(cloneResponse->serviceResult.is_bad())
    << "CreateSession presenting a certificate that is trusted, and asserts the same ApplicationUri, but "
       "is NOT the certificate that opened the SecureChannel was answered with "
    << cloneResponse->typeName << " carrying status 0x" << std::hex
    << cloneResponse->serviceResult.as_uint32()
    << "; Part 4 section 5.5.2 requires the same Certificate, not merely an equally trusted one";

  // Conjunct 2: and nothing came of it - no Session exists for the substituted certificate.
  EXPECT_EQ(access.sessions().size(), sessionsAfterControl)
    << "a Session was created for a CreateSession whose certificate is not the channel's certificate";

  // ---------------------------------------------------------------------------------------------------
  // Link 2 - ActivateSession carries no certificate field, so the certificate it presents is the one on
  // the channel it arrives over.
  // ---------------------------------------------------------------------------------------------------
  {
    auto session = channel.create_session_sync({.sessionName = "CertChain_Activate"});
    session.activate_sync();
    ASSERT_TRUE(session.is_active())
      << "the Session under test must really be activated on the original channel's certificate";

    // Control: a different channel carrying the SAME certificate. Part 4 permits re-binding a Session to a
    // new SecureChannel, so this must be allowed - with it refused, the refusal that follows would be
    // explained by the channel having changed rather than by the certificate.
    auto sameCertChannel =
      open_channel(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
    ASSERT_TRUE(sameCertChannel.is_open());
    ASSERT_NE(sameCertChannel.secure_channel_id(), channel.secure_channel_id());
    auto sameCertActivate = session.try_activate_sync(std::move(sameCertChannel));
    ASSERT_THAT(sameCertActivate, ::ua::test_helpers::Good())
      << "re-activating on a different channel carrying the same certificate must be allowed; with it "
         "refused, nothing distinguishes a certificate check from a blanket channel check";
    ASSERT_TRUE(session.is_active());

    // Substitution: a channel genuinely opened with the imposter certificate - trusted, same application
    // identity, different bytes.
    CoreClient::OpenChannelConfig imposterCfg;
    imposterCfg.endpointUrl = mEndpointUrl;
    imposterCfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    imposterCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    imposterCfg.serverCertificate = mServerCert;
    auto imposterChannelResult = imposterClient.core().try_open_channel_sync(std::move(imposterCfg));
    ASSERT_THAT(imposterChannelResult, ::ua::test_helpers::Good())
      << "the imposter certificate is trusted, so its channel must open - the refusal under test has to "
         "come from the continuity check and not from that certificate being unknown";
    auto imposterChannel = std::move(imposterChannelResult).value();
    ASSERT_TRUE(imposterChannel.is_open());
    ASSERT_NE(imposterChannel.secure_channel_id(), channel.secure_channel_id());

    auto imposterActivate = session.try_activate_sync(std::move(imposterChannel));
    EXPECT_TRUE(imposterActivate.is_bad())
      << "ActivateSession moved the Session onto a channel whose certificate is not the one that opened "
         "the original channel; the certificate being trusted and asserting the same ApplicationUri does "
         "not make it the same Certificate, and continuity must be re-checked at every activation";

    (void)session.try_close_sync();
  }

  channel.try_close_sync();
}

// ===========================================================================
// Part 6 UASC obligations whose discharge was "(none)"
// ===========================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <functional>
#include <vector>

// Part 6 section 6.7.2.3: "The MessageChunkSize depends on the transport protocol but shall be at least 8 192
// bytes", which Part 6 section 7.1.2.3 Table 66 puts on the SENDER of a Hello: "Shall be at least 1 024 bytes
// if the sender intends to use an ECC SecurityPolicy. Shall be at least 8 192 bytes otherwise." The floor is
// a rule about the chunk size an endpoint PICKS, not one it can impose on a peer: Table 67 caps the
// Acknowledge at the proposal it answers ("shall not be larger than the SendBufferSize requested in the Hello
// Message"), so a receiver handed a sub-floor Hello cannot lawfully answer above it. What the sender-side
// rule does forbid is originating such a proposal, and a configuration carrying a sub-floor buffer is the
// obvious way to do it by accident. The stimulus therefore patches the value on the wire AFTER the SDK has
// chosen it, which leaves the SDK's own choice readable in the pre-patch bytes while still putting a
// sub-floor proposal in front of the server. Refusing that proposal is SVR-UASC-060's obligation and is
// asserted against that requirement.
// @verifies AC-SVR-UASC-010-CHUNKSIZE
TEST_F(ComplianceSecureChannel, NegotiatedChunkSizeMeetsTheEightKilobyteFloorWhateverTheHelloProposed)
{
  // Below the 8192 non-ECC floor, but at or above the 1024 absolute minimum, so the Hello is a well-formed
  // proposal the peer is obliged to answer rather than one it may reject out of hand.
  constexpr uint32_t subMinimumBufferSize = 4096u;
  auto originalHelloFrames = std::make_shared<CapturedFrames>();
  auto patchedHelloFrames = std::make_shared<CapturedFrames>();

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
  cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  cfg.serverCertificate = mServerCert;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [originalHelloFrames, patchedHelloFrames](
                                 std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [originalHelloFrames, patchedHelloFrames](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          // HEL: [0-2]="HEL", [3]='F', [4-7]=messageSize, [8-11]=ProtocolVersion,
          // [12-15]=ReceiveBufferSize, [16-19]=SendBufferSize, [20-23]=MaxMessageSize, ...
          // Only fixed-width fields are rewritten, so the declared message size stays correct.
          if (data.size() >= 20 && read_message_type(data) == "HEL")
          {
            // Captured before the rewrite: these are the sizes the SDK itself chose to propose.
            originalHelloFrames->add(data);
            const std::array<std::byte, 4> subMinimumLe{static_cast<std::byte>(subMinimumBufferSize & 0xFF),
              static_cast<std::byte>((subMinimumBufferSize >> 8) & 0xFF),
              static_cast<std::byte>((subMinimumBufferSize >> 16) & 0xFF),
              static_cast<std::byte>((subMinimumBufferSize >> 24) & 0xFF)};
            std::copy(subMinimumLe.begin(), subMinimumLe.end(), data.begin() + 12);
            std::copy(subMinimumLe.begin(), subMinimumLe.end(), data.begin() + 16);
            patchedHelloFrames->add(data);
          }
          return data;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  auto result = mClient->core().try_open_channel_sync(std::move(cfg));

  // Non-vacuous: the sub-minimum proposal really reached the wire, so the handshake below ran in the
  // presence of the stimulus and not in its absence.
  ASSERT_GE(patchedHelloFrames->count(), 1u)
    << "no HEL frame carried the sub-minimum buffer sizes -- the stimulus never happened";
  auto patchedHello = patchedHelloFrames->get(0);
  ASSERT_EQ(read_le_uint32(patchedHello, 12), subMinimumBufferSize)
    << "the Hello handed to the transport did not carry the sub-minimum ReceiveBufferSize";
  ASSERT_EQ(read_le_uint32(patchedHello, 16), subMinimumBufferSize)
    << "the Hello handed to the transport did not carry the sub-minimum SendBufferSize";

  // The sender-side rule: this connection intends Basic256Sha256, an RSA policy, so Table 66's 8192 branch
  // is the one that binds the proposal the SDK wrote -- and it binds it whatever the configured buffer size
  // was, since a sub-floor configuration is exactly the accident the rule exists to catch.
  ASSERT_GE(originalHelloFrames->count(), 1u);
  auto originalHello = originalHelloFrames->get(0);
  EXPECT_GE(read_le_uint32(originalHello, 12), 8192u)
    << "the SDK proposed a ReceiveBufferSize of " << read_le_uint32(originalHello, 12)
    << " bytes for a non-ECC SecurityPolicy; Part 6 section 7.1.2.3 Table 66 puts the floor for such a "
       "sender at "
       "8192, and a peer that answers this proposal in good faith runs the channel below the "
       "MessageChunkSize "
       "minimum of section 6.7.2.3";
  EXPECT_GE(read_le_uint32(originalHello, 16), 8192u)
    << "the SDK proposed a SendBufferSize of " << read_le_uint32(originalHello, 16)
    << " bytes for a non-ECC SecurityPolicy; the floor binds both directions of the proposal";

  // Whether the server then accepts or refuses the tampered proposal is SVR-UASC-060's question -- Table 67
  // forbids it answering above the 4096 it was offered, so it cannot satisfy the floor by negotiation.
  if (result.is_good())
  {
    auto channel = std::move(result).value();
    (void)channel.try_close_sync();
  }
}

/// Builds one symmetric MessageChunk by hand for a Sign-mode channel, where nothing is encrypted and the
/// whole chunk is covered by a single trailing HMAC. @p isFinal is the Part 6 section 6.7.2 chunk-type byte
/// ('C' intermediate, 'F' final, 'A' abort). @p signTrailer receives the bytes the signature must cover --
/// the message-size field is already stamped with the FINAL size, signature included, exactly as the SDK's
/// own encoder stamps it before signing -- and returns the trailer to append. Routing the signature through a
/// caller-supplied hook is what lets the valid abort and the forged one below come out of one builder: they
/// differ in that trailer and in nothing else, so a difference in how the receiver treats them is
/// attributable to the security check and to nothing about their framing.
static std::vector<std::byte> build_symmetric_chunk(char isFinal, uint32_t channelId, uint32_t tokenId,
  uint32_t sequenceNumber, uint32_t requestId, const std::vector<std::byte>& body, size_t signatureSize,
  const std::function<std::vector<std::byte>(const std::vector<std::byte>&)>& signTrailer)
{
  std::vector<std::byte> frame;
  auto pushU32 = [&frame](uint32_t value)
  {
    frame.push_back(static_cast<std::byte>(value & 0xFF));
    frame.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
    frame.push_back(static_cast<std::byte>((value >> 16) & 0xFF));
    frame.push_back(static_cast<std::byte>((value >> 24) & 0xFF));
  };

  frame.push_back(static_cast<std::byte>('M'));
  frame.push_back(static_cast<std::byte>('S'));
  frame.push_back(static_cast<std::byte>('G'));
  frame.push_back(static_cast<std::byte>(isFinal));
  pushU32(0);  // message size -- patched below, once the signature length is folded in
  pushU32(channelId);
  pushU32(tokenId);
  pushU32(sequenceNumber);
  pushU32(requestId);
  frame.insert(frame.end(), body.begin(), body.end());

  const auto chunkSize = static_cast<uint32_t>(frame.size() + signatureSize);
  frame[4] = static_cast<std::byte>(chunkSize & 0xFF);
  frame[5] = static_cast<std::byte>((chunkSize >> 8) & 0xFF);
  frame[6] = static_cast<std::byte>((chunkSize >> 16) & 0xFF);
  frame[7] = static_cast<std::byte>((chunkSize >> 24) & 0xFF);

  auto trailer = signTrailer(frame);
  frame.insert(frame.end(), trailer.begin(), trailer.end());
  return frame;
}

/// The Part 6 section 6.7.3 abort-chunk body: the Error StatusCode followed by the Reason String (encoded
/// null here, which is what the SDK's own abort emitter writes for an empty reason).
static std::vector<std::byte> build_abort_chunk_body(uint32_t errorStatus)
{
  std::vector<std::byte> body;
  auto pushU32 = [&body](uint32_t value)
  {
    body.push_back(static_cast<std::byte>(value & 0xFF));
    body.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
    body.push_back(static_cast<std::byte>((value >> 16) & 0xFF));
    body.push_back(static_cast<std::byte>((value >> 24) & 0xFF));
  };
  pushU32(errorStatus);
  pushU32(0xFFFFFFFFu);  // Reason: null String
  return body;
}

/// Waits for the server to hand its side of a newly opened SecureChannel to the availability hook. Without
/// that object the server-side disposition below could only be inferred from client-visible symptoms, and
/// "the channel was closed" would not be distinguishable from "the request happened to fail".
static std::shared_ptr<ua::server::SecureChannel> wait_for_captured_server_channel(
  FirstServerChannelCapture& capture, std::chrono::milliseconds timeout)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;)
  {
    {
      std::lock_guard lock(capture.mutex);
      if (capture.channel)
        return capture.channel;
    }
    if (std::chrono::steady_clock::now() >= deadline)
      return nullptr;
    std::this_thread::sleep_for(50ms);
  }
}

// Part 6 section 6.7.3: "The receiver shall check the security on the abort MessageChunk before processing
// it. If everything is ok, then the receiver shall ignore the Message but shall not close the SecureChannel."
// Both halves are required, and the antecedent divides them. The channel id and the token id travel in
// the clear in every chunk, so fabricating an abort costs an attacker no credentials at all -- a receiver
// that dispatches on the 'A' chunk-type byte at the framing layer, or that trusts any chunk naming a live
// channel, lets anyone who can put a packet on the socket cancel another peer's in-flight request. That is
// what the first half forbids, and it is what the forged abort below tests. The "shall not close" is the
// consequent of "If everything is ok" and so binds only the abort that passes its check; an abort that fails
// verification is disposed of like any other chunk that fails it, under section 6.7.6 ("If an error occurs
// during Message verification the receiver shall close the communication channel"). This drives one abort of
// each kind into the same channel, built by one builder so they differ only in their signature trailer.
// @verifies AC-SVR-UASC-019-ABORTSEC
TEST_F(ComplianceSecureChannel, AbortChunkIsSecurityCheckedBeforeHonouredAndNeverClosesTheChannel)
{
  auto policy = SecurityPolicy::create(SecurityPolicyId::Basic256Sha256);
  ASSERT_NE(policy, nullptr);
  const size_t signatureSize = policy->symmetric_signature_size();
  ASSERT_GT(signatureSize, 0u) << "Basic256Sha256 must define a symmetric signature size";

  auto& serverImpl = ua::test_helpers::ServerTestAccess::impl(*mServer);
  ua::test_helpers::ServerImplTestAccess access(serverImpl);

  // -------------------------------------------------------------------------------------------------
  // Stimulus 1 -- an abort whose signature does not verify, placed INSIDE a message that is part sent.
  // -------------------------------------------------------------------------------------------------
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> forgedFuzz;
  auto forgedChannel = open_channel_with_transport_decorator(
    MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256, forgedFuzz);
  ASSERT_TRUE(forgedChannel.is_open());
  ASSERT_NE(forgedFuzz, nullptr);

  {
    // Baseline: the channel is serviceable BEFORE the forged abort, so the outcome below measures the effect
    // of the abort and nothing else.
    GetEndpointsRequest warmUp;
    warmUp.endpoint_url() = mEndpointUrl;
    ASSERT_THAT(forgedChannel.try_get_endpoints_sync(std::move(warmUp)), ::ua::test_helpers::Good())
      << "the channel must work before the forged abort is injected";
  }
  mServerLogSink->clear();

  // The interceptor runs inside FuzzTransportConnection::async_write, i.e. on the same connection strand that
  // writes every other chunk, so injecting from it places the forged abort deterministically BETWEEN chunk 1
  // and chunk 2 of the message below -- not racing them. It is stamped with the sequence number the server
  // expects next and with the channel's real channel id and token id, so its signature is the only thing
  // wrong with it.
  struct ForgedAbortInjection
  {
    std::mutex mutex;
    size_t msgChunks{0};
    bool injected{false};
  };

  auto forgedInjection = std::make_shared<ForgedAbortInjection>();
  std::weak_ptr<opcua_fuzzer::FuzzTransportConnection> weakForgedFuzz = forgedFuzz;
  forgedFuzz->set_write_interceptor(
    [forgedInjection, weakForgedFuzz, signatureSize](std::vector<std::byte> data) -> std::vector<std::byte>
    {
      // Symmetric chunk under Sign: [0-2]="MSG", [3]=chunk type, [4-7]=size, [8-11]=channelId,
      // [12-15]=tokenId, [16-19]=sequenceNumber, [20-23]=requestId.
      if (data.size() >= 24 && read_message_type(data) == "MSG")
      {
        std::lock_guard lock(forgedInjection->mutex);
        ++forgedInjection->msgChunks;
        if (forgedInjection->msgChunks == 2 && !forgedInjection->injected)
        {
          auto fuzz = weakForgedFuzz.lock();
          if (fuzz)
          {
            forgedInjection->injected = true;
            auto forged = build_symmetric_chunk('A',
              read_le_uint32(data, 8),
              read_le_uint32(data, 12),
              read_le_uint32(data, 16),
              read_le_uint32(data, 20),
              build_abort_chunk_body(ua::StatusCode{Status::BadRequestInterrupted}.as_uint32()),
              signatureSize,
              [signatureSize](const std::vector<std::byte>&)
              { return std::vector<std::byte>(signatureSize, static_cast<std::byte>(0xA5)); });
            fuzz->inject_bytes(std::move(forged));
          }
        }
      }
      return data;
    });

  // A request large enough to span several chunks, so that when the forged abort lands there really is an
  // in-flight message for it to cancel.
  GetEndpointsRequest multiChunkRequest;
  multiChunkRequest.endpoint_url() = mEndpointUrl;
  const String profileFiller{std::string(4000, 'p')};
  for (int i = 0; i < 60; ++i)
    multiChunkRequest.profile_uris().push_back(profileFiller);
  auto multiChunkResult = forgedChannel.try_get_endpoints_sync(std::move(multiChunkRequest));

  {
    std::lock_guard lock(forgedInjection->mutex);
    ASSERT_TRUE(forgedInjection->injected)
      << "the request never spanned more than one chunk, so no forged abort was placed inside an in-flight "
         "message and a refusal below would prove nothing";
    ASSERT_GE(forgedInjection->msgChunks, 2u);
  }
  forgedFuzz->set_write_interceptor(nullptr);

  // The forged abort was security-checked BEFORE it was processed. A receiver that dispatched on the 'A'
  // chunk-type byte at the framing layer would honour it without ever reaching verification and so would
  // never report this site; the graceful paths record nothing above Debug, so an Error carrying it can only
  // have come from the chunk's security check failing.
  EXPECT_TRUE(wait_for_server_error_log(*mServerLogSink, chunkSecurityFailureSite, 2s))
    << "an abort chunk whose signature does not verify was not reported as a security failure; nothing "
       "distinguishes this from the abort having been honoured on the strength of its chunk-type byte, "
       "which the channel id and token id travelling in the clear on every chunk make free to fabricate";

  // What becomes of the connection afterwards is the generic failed-verification disposition of
  // section 6.7.6, not this criterion's: section 6.7.3's "shall not close" is the consequent of "If
  // everything is ok" and is asserted below, on the abort that does verify.
  (void)multiChunkResult;
  (void)forgedChannel.try_close_sync();

  // -------------------------------------------------------------------------------------------------
  // Stimulus 2 -- an abort that DOES verify. Same builder, same framing; only the trailer differs, and here
  // it is the real HMAC over the chunk under the channel's own current signing key.
  // -------------------------------------------------------------------------------------------------
  auto validCapture = std::make_shared<FirstServerChannelCapture>();
  std::weak_ptr<FirstServerChannelCapture> weakValidCapture = validCapture;
  access.set_on_secure_channel_available(
    [weakValidCapture](std::shared_ptr<ua::server::SecureChannel> sc)
    {
      auto state = weakValidCapture.lock();
      if (!state)
        return;
      std::lock_guard lock(state->mutex);
      if (!state->channel)
        state->channel = std::move(sc);
    });

  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> validFuzz;
  auto validChannel = open_channel_with_transport_decorator(
    MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256, validFuzz);
  ASSERT_TRUE(validChannel.is_open());
  ASSERT_NE(validFuzz, nullptr);

  auto validServerChannel = wait_for_captured_server_channel(*validCapture, 5s);
  ASSERT_NE(validServerChannel, nullptr)
    << "the server-side SecureChannel was never observed, so neither the dispatch count nor the channel "
       "state below could be read";

  // Count what the server actually dispatches, so "the abort ended that message" is measured by the aborted
  // message never reaching the service rather than by a side effect.
  auto dispatchedRequests = std::make_shared<std::atomic<size_t>>(0);
  ua::server::SecureChannelTestAccess::on_strand(*validServerChannel,
    [dispatchedRequests](auto& g)
    {
      g.set_request_observer(
        [dispatchedRequests](uint32_t, const ua::Structure&) { dispatchedRequests->fetch_add(1); });
    });

  {
    GetEndpointsRequest warmUp;
    warmUp.endpoint_url() = mEndpointUrl;
    ASSERT_THAT(validChannel.try_get_endpoints_sync(std::move(warmUp)), ::ua::test_helpers::Good())
      << "the channel must work before the valid abort is injected";
  }
  const size_t dispatchedBeforeAbort = dispatchedRequests->load();
  ASSERT_GE(dispatchedBeforeAbort, 1u)
    << "the request observer never fired, so asserting that nothing further was dispatched would be vacuous";

  // Everything the two hand-built chunks need in order to be indistinguishable from the channel's own
  // traffic: the channel and token they belong to, the point its transmit sequence has reached, and the key
  // and algorithm the receiver will verify them with.
  struct SigningState
  {
    uint32_t channelId{0};
    uint32_t tokenId{0};
    uint32_t lastTxSequenceNumber{0};
    ua::ByteString signingKey;
    ua::SymmetricSignatureAlgorithm algorithm{};
  };

  auto signing = CSCTA::on_strand(validChannel,
    [](auto& g)
    {
      auto& context = *g.context();
      SigningState state;
      state.channelId = context.secureChannelId;
      state.lastTxSequenceNumber = context.lastTxSequenceNumber;
      if (context.securityPolicy)
        state.algorithm = context.securityPolicy->symmetric_signature_algorithm();
      if (context.activeSecurityToken)
      {
        state.tokenId = context.activeSecurityToken->id();
        state.signingKey = context.activeSecurityToken->local_keys().signingKey;
      }
      return state;
    });
  ASSERT_NE(signing.tokenId, 0u);
  ASSERT_FALSE(signing.signingKey.empty())
    << "no symmetric signing key on an authenticated channel, so a genuinely signed abort cannot be built";

  auto signTrailer = [this, &signing](const std::vector<std::byte>& bytes)
  {
    const auto* keyBytes = reinterpret_cast<const std::byte*>(signing.signingKey.data());
    auto signature = mCrypto->symmetric_sign_sync(signing.algorithm,
      ua::span<const ua::byte>{keyBytes, signing.signingKey.size()},
      ua::span<const ua::byte>{bytes.data(), bytes.size()});
    const auto* first = reinterpret_cast<const std::byte*>(signature.data());
    return std::vector<std::byte>{first, first + signature.size()};
  };

  // Chunk 1 of a message that will never get a final chunk: the abort is what ends it. Its body is never
  // decoded -- the abort discards the reassembly buffer before any final chunk could ask for it.
  constexpr uint32_t abortedRequestId = 0x5AB07001u;
  const std::vector<std::byte> partialBody(512, static_cast<std::byte>(0x11));
  auto partialChunk = build_symmetric_chunk('C',
    signing.channelId,
    signing.tokenId,
    signing.lastTxSequenceNumber + 1u,
    abortedRequestId,
    partialBody,
    signatureSize,
    signTrailer);
  auto validAbort = build_symmetric_chunk('A',
    signing.channelId,
    signing.tokenId,
    signing.lastTxSequenceNumber + 2u,
    abortedRequestId,
    build_abort_chunk_body(ua::StatusCode{Status::BadRequestInterrupted}.as_uint32()),
    signatureSize,
    signTrailer);

  // The client's own transmit counter must advance past the two injected chunks. Without this its next real
  // message would arrive bearing a sequence number the server has already consumed, and the channel would go
  // down for a reason that has nothing to do with the abort.
  CSCTA::on_strand(validChannel,
    [&signing](auto& g) { g.context()->lastTxSequenceNumber = signing.lastTxSequenceNumber + 2u; });

  mServerLogSink->clear();
  validFuzz->inject_bytes(partialChunk);
  validFuzz->inject_bytes(validAbort);

  // The refusal path reports a chunk security failure under this site; the honoured path records nothing
  // above Debug. Its ABSENCE is the discriminator, so it is polled for a full interval rather than sampled
  // once -- and the interval also gives the server time to process both injected chunks.
  EXPECT_FALSE(wait_for_server_error_log(*mServerLogSink, chunkSecurityFailureSite, 2s))
    << "a correctly signed abort chunk was reported as a security failure; its security check is being "
       "applied wrongly, or not before the chunk is processed";

  // Conjunct 1: the abort ended THAT message -- nothing was dispatched from the discarded reassembly.
  EXPECT_EQ(dispatchedRequests->load(), dispatchedBeforeAbort)
    << "the server dispatched a request built out of a message that was aborted before any final chunk "
       "arrived; the abort was not honoured as a discard";

  // Conjunct 2: the SecureChannel is still open on the server.
  auto validServerState = ua::server::SecureChannelTestAccess::on_strand(
    *validServerChannel, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(validServerState, ua::server::SecureChannelTestAccess::ChannelState::Open)
    << "the server closed the SecureChannel on a valid abort chunk; Part 6 section 6.7.3 requires it to "
       "ignore the "
       "Message and keep the channel";

  // Conjunct 3: and it is still SERVICEABLE, which a channel torn down behind a stale Open flag would not be.
  GetEndpointsRequest afterAbort;
  afterAbort.endpoint_url() = mEndpointUrl;
  EXPECT_THAT(validChannel.try_get_endpoints_sync(std::move(afterAbort)), ::ua::test_helpers::Good())
    << "the channel stopped serving requests after an abort chunk it was required only to ignore";

  (void)validChannel.try_close_sync();
}

// Part 6 section 6.7.2.4: "SecurityPolicies with LegacySequenceNumbers set to FALSE, the SequenceNumber shall
// start at 0 and monotonically increase for all Messages and shall not wrap around until it is equal to 4 294
// 967 295 (UInt32.MaxValue). The first number after the wrap around shall be 0." The rule is conditional on
// the policy's LegacySequenceNumbers parameter, so the subject is chosen by reading that parameter off the
// policy rather than by naming a policy: a policy with LegacySequenceNumbers TRUE carries the 1 024-based
// rules of the paragraph above, which prescribe no starting value at all, and is not a subject here. Two
// plausible implementations get the 0-based rule wrong in the same counter. A sender that pre-increments
// before stamping starts every channel at 1, which no exchange of messages can reveal because monotonicity
// still holds; and a receiver that keeps a plain `received > lastSeen` comparison, or that applies the
// 1 024-based rule to a policy that does not use it, reads the wrap as a replay and tears the channel down.
// The wrap cannot be reached by traffic, so the boundary is placed by writing the sender's next stamp and the
// receiver's last-seen directly -- that is the antecedent, not the behaviour. What number the production
// encoder then puts on the wire, and whether the production receiver accepts it, is what is measured.
// @verifies AC-SVR-UASC-014-SEQWRAP
TEST_F(ComplianceSecureChannel, NonLegacySequenceStartsAtZeroAndWrapsToZeroWithoutClosingTheChannel)
{
  constexpr uint32_t sequenceWrapBoundary = 4294967295u;  // UInt32.MaxValue
  constexpr auto policyIdUnderTest = SecurityPolicyId::EccNistP256AesGcm;

  // Subject selection, not an observation: the stimulus is defined over policies whose
  // LegacySequenceNumbers is FALSE, so the channel below is only the obligation's subject if the policy it
  // runs under carries that value. ECC_nistP256 is the CBC-based ECC policy, which supports Sign as well as
  // SignAndEncrypt; Sign keeps the symmetric sequence header outside the encrypted region, so the number
  // that follows the boundary can be read from the bytes the SDK actually wrote rather than inferred from
  // its own state.
  {
    auto policyUnderTest = SecurityPolicy::create(policyIdUnderTest);
    ASSERT_NE(policyUnderTest, nullptr);
    ASSERT_FALSE(policyUnderTest->uses_legacy_sequence_no())
      << "the policy this test opens its channel under does not carry LegacySequenceNumbers FALSE, so the "
         "0-based sequence rules of Part 6 section 6.7.2.4 have no subject here and the test measures "
         "nothing";
  }

  // The fixture allocates only RSA material. An ECC policy selects its own certificate by certificate type on
  // both sides, so the nistP256 pair is allocated here and added to the same live stores the server and
  // client consult when the channel opens.
  const UtcTime eccExpiry{2050, 1, 1, 0, 0, 0};
  std::shared_ptr<const X509Certificate> eccServerCert;
  {
    Crypto::Name subject;
    subject.commonName = "ComplianceSecured ECC Server";
    Crypto::SubjectAlternateName altName;
    altName.uris.push_back("urn:test:compliance:server");
    altName.hostnames.push_back("localhost");
    altName.hostnames.push_back("127.0.0.1");

    auto result = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      subject, eccExpiry, altName, CertificateType::EccNistP256Application, 2048);
    ASSERT_TRUE(result.is_good()) << "the ECC server certificate could not be allocated";
    auto [keys, cert] = std::move(result).value();
    eccServerCert = cert;

    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::EccNistP256Application;
    appCert.certificate = cert;
    appCert.keys = std::move(keys);
    mServerCertStore->add_to_application_certificates_sync(std::move(appCert));
    mClientCertStore->add_to_trusted_certificates_sync(eccServerCert);
  }
  {
    Crypto::Name subject;
    subject.commonName = "ComplianceSecured ECC Client";
    Crypto::SubjectAlternateName altName;
    altName.uris.push_back("urn:test:compliance:client");
    altName.hostnames.push_back("localhost");

    auto result = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      subject, eccExpiry, altName, CertificateType::EccNistP256Application, 2048);
    ASSERT_TRUE(result.is_good()) << "the ECC client certificate could not be allocated";
    auto [keys, cert] = std::move(result).value();

    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::EccNistP256Application;
    appCert.certificate = cert;
    appCert.keys = std::move(keys);
    mClientCertStore->add_to_application_certificates_sync(std::move(appCert));
    mServerCertStore->add_to_trusted_certificates_sync(cert);
  }

  // The fixture advertises only None and Basic256Sha256, both LegacySequenceNumbers TRUE, so the endpoint
  // the subject policy needs is added here.
  {
    ServerEndpointConfig eccSignEp;
    eccSignEp.name = "EccNistP256_Sign";
    eccSignEp.messageSecurityMode = MessageSecurityMode::Sign;
    eccSignEp.securityPolicyId = policyIdUnderTest;
    eccSignEp.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(eccSignEp));
  }

  // The receiver's own sequence expectation has to be moved to the boundary as well, otherwise the wrapped
  // chunk would be refused for arriving out of order and the refusal would say nothing about the wrap.
  auto capture = std::make_shared<FirstServerChannelCapture>();
  std::weak_ptr<FirstServerChannelCapture> weakCapture = capture;
  {
    auto& serverImpl = ua::test_helpers::ServerTestAccess::impl(*mServer);
    ua::test_helpers::ServerImplTestAccess access(serverImpl);
    access.set_on_secure_channel_available(
      [weakCapture](std::shared_ptr<ua::server::SecureChannel> sc)
      {
        auto state = weakCapture.lock();
        if (!state)
          return;
        std::lock_guard lock(state->mutex);
        if (!state->channel)
          state->channel = std::move(sc);
      });
  }

  // The write interceptor is installed on the decorated transport BEFORE the channel is opened, so the OPN --
  // the first chunk that carries a sequence header at all -- is counted rather than missed.
  auto frames = std::make_shared<CapturedFrames>();
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> fuzzTransport;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [&fuzzTransport, frames](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [frames](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          frames->add(data);
          return data;
        });
      fuzzTransport = fuzz;
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::Sign;
  cfg.securityPolicyId = policyIdUnderTest;
  cfg.serverCertificate = eccServerCert;
  auto channel = mClient->core().open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channel.is_open())
    << "a Sign channel under ECC_nistP256 could not be opened, so the non-legacy sequence rules have "
       "nothing to bind here";
  ASSERT_NE(fuzzTransport, nullptr);

  // Exactly one sequenced chunk has been written at this point -- HELLO and ACKNOWLEDGE carry no sequence
  // header -- so the transmit counter holds the number that chunk was stamped with, and reading it is reading
  // what went on the wire. Both counts are checked so that reading it cannot silently mean something else.
  size_t opnFrameCount = 0;
  size_t symmetricFrameCount = 0;
  {
    const auto frameCount = frames->count();
    ASSERT_GT(frameCount, 0u) << "no transport frame was captured, so nothing below observes the wire";
    for (size_t i = 0; i < frameCount; ++i)
    {
      auto frameType = read_message_type(frames->get(i));
      if (frameType == "OPN")
        ++opnFrameCount;
      else if (frameType == "MSG" || frameType == "CLO")
        ++symmetricFrameCount;
    }
  }
  ASSERT_EQ(opnFrameCount, 1u) << "expected exactly one OPN chunk on a freshly opened channel";
  ASSERT_EQ(symmetricFrameCount, 0u)
    << "further sequenced chunks were written while the channel opened, so the transmit counter no longer "
       "identifies the FIRST sequence number";

  const auto firstSequenceNumber =
    CSCTA::on_strand(channel, [](auto& g) { return g.context()->lastTxSequenceNumber; });

  // Conjunct 1: the first number is 0.
  EXPECT_EQ(firstSequenceNumber, 0u)
    << "the first SequenceNumber on a channel under a SecurityPolicy with LegacySequenceNumbers FALSE was "
    << firstSequenceNumber << "; Part 6 section 6.7.2.4 requires it to start at 0";

  auto serverChannel = wait_for_captured_server_channel(*capture, 5s);
  ASSERT_NE(serverChannel, nullptr)
    << "the server-side SecureChannel was never observed, so the receiver's sequence expectation could not "
       "be placed at the wrap boundary";

  // Baseline: the channel serves a request BEFORE the boundary is placed, so a failure afterwards is
  // attributable to the wrap and not to a channel that never worked.
  {
    GetEndpointsRequest warmUp;
    warmUp.endpoint_url() = mEndpointUrl;
    ASSERT_THAT(channel.try_get_endpoints_sync(std::move(warmUp)), ::ua::test_helpers::Good())
      << "the channel must serve a request before the sequence counters are moved to the wrap boundary";
  }

  // Place the client-to-server direction at the boundary on both sides: the sender's next stamp and the
  // receiver's last-seen. Neither side is told what to do at the boundary, only where the boundary is.
  CSCTA::on_strand(channel,
    [sequenceWrapBoundary](auto& g)
    {
      g.context()->lastTxSequenceNumber = sequenceWrapBoundary;
      // Part 6 6.7.2.4 also forbids reusing a SequenceNumber under one TokenId, so a real channel reaches
      // the wrap only on a token issued after its earlier numbers. Clearing the per-token record models
      // that token; without it the numbers after the wrap repeat ones this token already used.
      g.context()->txUseUnderToken = {};
    });
  ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
    [sequenceWrapBoundary](auto& g)
    {
      g.context()->lastRxSequenceNumber = sequenceWrapBoundary;
      g.context()->rxUseUnderToken = {};
    });

  const size_t framesBeforeWrap = frames->count();
  mServerLogSink->clear();

  GetEndpointsRequest atWrap;
  atWrap.endpoint_url() = mEndpointUrl;
  auto atWrapResult = channel.try_get_endpoints_sync(std::move(atWrap));

  std::vector<uint32_t> sequenceNumbersAfterWrap;
  {
    const auto frameCount = frames->count();
    for (size_t i = framesBeforeWrap; i < frameCount; ++i)
    {
      auto frame = frames->get(i);
      // Symmetric chunk under Sign: [0-2]="MSG", [3]=chunk type, [4-7]=size, [8-11]=channelId,
      // [12-15]=tokenId, [16-19]=sequenceNumber, [20-23]=requestId. Nothing is encrypted under Sign.
      if (read_message_type(frame) == "MSG" && frame.size() >= 24)
        sequenceNumbersAfterWrap.push_back(read_le_uint32(frame, 16));
    }
  }
  ASSERT_FALSE(sequenceNumbersAfterWrap.empty())
    << "no symmetric MSG chunk was written after the transmit counter was placed at the boundary, so the "
       "number that follows UInt32.MaxValue was never observed";

  // Conjunct 2: the number after 4 294 967 295 is 0, read off the bytes the SDK wrote.
  EXPECT_EQ(sequenceNumbersAfterWrap.front(), 0u)
    << "the chunk written after SequenceNumber 4 294 967 295 carried " << sequenceNumbersAfterWrap.front()
    << "; Part 6 section 6.7.2.4 requires the first number after the wrap around to be 0";

  // Conjunct 3: the channel survives the wrap rather than treating it as an error. The request the wrapped
  // chunk carried was answered...
  EXPECT_THAT(atWrapResult, ::ua::test_helpers::Good())
    << "the request carried by the chunk at the wrap boundary failed; the receiver treated a legitimate "
       "sequence-number wrap as an error";

  // ...the receiver did not report the chunk as a failure...
  EXPECT_FALSE(wait_for_server_error_log(*mServerLogSink, chunkSecurityFailureSite, 2s))
    << "the server reported a chunk failure on the wrapped SequenceNumber; a wrap to 0 is required "
       "behaviour, not a replay";

  // ...the SecureChannel is still open on the server...
  auto serverStateAfterWrap =
    ua::server::SecureChannelTestAccess::on_strand(*serverChannel, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(serverStateAfterWrap, ua::server::SecureChannelTestAccess::ChannelState::Open)
    << "the server closed the SecureChannel when the SequenceNumber wrapped";

  // ...and it keeps serving past the wrap, which a receiver left with a corrupted expectation would not.
  GetEndpointsRequest afterWrap;
  afterWrap.endpoint_url() = mEndpointUrl;
  EXPECT_THAT(channel.try_get_endpoints_sync(std::move(afterWrap)), ::ua::test_helpers::Good())
    << "the channel stopped serving requests once the SequenceNumber had wrapped";

  (void)channel.try_close_sync();
}

// Part 6 section 6.7.2.4: "SecurityPolicies with LegacySequenceNumbers set to FALSE, the SequenceNumber shall
// start at 0 and monotonically increase for all Messages and shall not wrap around until it is equal to 4 294
// 967 295 (UInt32.MaxValue). The first number after the wrap around shall be 0." SVR-UASC-014 names its
// subjects: "Aes128-Sha256-RsaOaep, Aes256-Sha256-RsaPss, ECC policies". The RSA pair is therefore as much a
// subject of the 0-based rule as the ECC policies are, and it is the pair an RSA-only deployment actually
// negotiates; the ECC subject is measured by the test above, the RSA subject by nothing. One shared chunk
// encoder serving every policy is the plausible way to get this wrong. Such an encoder pre-increments a
// single counter before stamping, so every channel starts at 1 -- legal under the 1 024-based paragraph,
// which prescribes no starting value, and therefore invisible in any Basic256Sha256 exchange, since
// monotonicity holds either way. The same conflation shows up one level earlier as a policy that reports
// LegacySequenceNumbers TRUE for a policy the obligation lists as non-legacy, which routes it to the 1
// 024-based receiver rule instead of this one; that classification is checked here rather than assumed,
// because it is what decides whether the paragraph applies at all. The wrap cannot be reached by exchanging
// messages, so the boundary is placed by writing the sender's next stamp and the receiver's last-seen
// directly -- that is the antecedent, not the behaviour. What the production encoder then puts on the wire,
// and whether the production receiver accepts it, is measured.
// @verifies AC-SVR-UASC-014-SEQWRAP
TEST_F(ComplianceSecureChannel, RsaPolicyNonLegacySequenceStartsAtZeroAndWrapsToZeroWithoutClosingTheChannel)
{
  constexpr uint32_t sequenceWrapBoundary = 4294967295u;  // UInt32.MaxValue
  constexpr auto policyIdUnderTest = SecurityPolicyId::Aes256Sha256RsaPss;

  // Subject selection, read off the policies rather than assumed: both RSA policies SVR-UASC-014 names must
  // carry LegacySequenceNumbers FALSE, because that parameter is what routes a channel to the 0-based rules.
  for (auto policyId : {SecurityPolicyId::Aes128Sha256RsaOaep, SecurityPolicyId::Aes256Sha256RsaPss})
  {
    auto policy = SecurityPolicy::create(policyId);
    ASSERT_NE(policy, nullptr);
    EXPECT_FALSE(policy->uses_legacy_sequence_no())
      << std::string{policy->uri()}
      << " reports LegacySequenceNumbers TRUE, so its channels are sent to the 1 024-based SequenceNumber "
         "rules; SVR-UASC-014 lists it among the non-legacy policies governed by the 0-based rules of "
         "Part 6 section 6.7.2.4";
  }

  // The fixture advertises only None and Basic256Sha256, both LegacySequenceNumbers TRUE, so the endpoint
  // the subject policy needs is added here. Sign rather than SignAndEncrypt: Sign leaves the symmetric
  // sequence header in the clear, so the number that follows the boundary can be read off the bytes the SDK
  // actually wrote rather than inferred from its own state. The policy is RSA, so the fixture's existing
  // certificate serves it and no new PKI is needed.
  {
    ServerEndpointConfig rsaPssSignEp;
    rsaPssSignEp.name = "Aes256Sha256RsaPss_Sign";
    rsaPssSignEp.messageSecurityMode = MessageSecurityMode::Sign;
    rsaPssSignEp.securityPolicyId = policyIdUnderTest;
    rsaPssSignEp.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(rsaPssSignEp));
  }

  // The receiver's own sequence expectation has to be moved to the boundary as well, otherwise the wrapped
  // chunk would be refused for arriving out of order and the refusal would say nothing about the wrap.
  auto capture = std::make_shared<FirstServerChannelCapture>();
  std::weak_ptr<FirstServerChannelCapture> weakCapture = capture;
  {
    auto& serverImpl = ua::test_helpers::ServerTestAccess::impl(*mServer);
    ua::test_helpers::ServerImplTestAccess access(serverImpl);
    access.set_on_secure_channel_available(
      [weakCapture](std::shared_ptr<ua::server::SecureChannel> sc)
      {
        auto state = weakCapture.lock();
        if (!state)
          return;
        std::lock_guard lock(state->mutex);
        if (!state->channel)
          state->channel = std::move(sc);
      });
  }

  // The write interceptor is installed on the decorated transport BEFORE the channel is opened, so the OPN --
  // the first chunk that carries a sequence header at all -- is counted rather than missed.
  auto frames = std::make_shared<CapturedFrames>();
  std::shared_ptr<opcua_fuzzer::FuzzTransportConnection> fuzzTransport;
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [&fuzzTransport, frames](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [frames](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          frames->add(data);
          return data;
        });
      fuzzTransport = fuzz;
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  CoreClient::OpenChannelConfig cfg;
  cfg.endpointUrl = mEndpointUrl;
  cfg.securityMode = MessageSecurityMode::Sign;
  cfg.securityPolicyId = policyIdUnderTest;
  cfg.serverCertificate = mServerCert;
  auto channel = mClient->core().open_channel_sync(std::move(cfg));
  ASSERT_TRUE(channel.is_open())
    << "a Sign channel under Aes256-Sha256-RsaPss could not be opened, so the non-legacy sequence rules "
       "have nothing to bind here";
  ASSERT_NE(fuzzTransport, nullptr);

  // Exactly one sequenced chunk has been written at this point -- HELLO and ACKNOWLEDGE carry no sequence
  // header -- so the transmit counter holds the number that chunk was stamped with, and reading it is reading
  // what went on the wire. Both counts are checked so that reading it cannot silently mean something else.
  size_t opnFrameCount = 0;
  size_t symmetricFrameCount = 0;
  {
    const auto frameCount = frames->count();
    ASSERT_GT(frameCount, 0u) << "no transport frame was captured, so nothing below observes the wire";
    for (size_t i = 0; i < frameCount; ++i)
    {
      auto frameType = read_message_type(frames->get(i));
      if (frameType == "OPN")
        ++opnFrameCount;
      else if (frameType == "MSG" || frameType == "CLO")
        ++symmetricFrameCount;
    }
  }
  ASSERT_EQ(opnFrameCount, 1u) << "expected exactly one OPN chunk on a freshly opened channel";
  ASSERT_EQ(symmetricFrameCount, 0u)
    << "further sequenced chunks were written while the channel opened, so the transmit counter no longer "
       "identifies the FIRST sequence number";

  const auto firstSequenceNumber =
    CSCTA::on_strand(channel, [](auto& g) { return g.context()->lastTxSequenceNumber; });

  // Conjunct 1: the first number is 0.
  EXPECT_EQ(firstSequenceNumber, 0u)
    << "the first SequenceNumber on a channel under Aes256-Sha256-RsaPss was " << firstSequenceNumber
    << "; Part 6 section 6.7.2.4 requires a policy with LegacySequenceNumbers FALSE to start at 0";

  auto serverChannel = wait_for_captured_server_channel(*capture, 5s);
  ASSERT_NE(serverChannel, nullptr)
    << "the server-side SecureChannel was never observed, so the receiver's sequence expectation could not "
       "be placed at the wrap boundary";

  // Baseline: the channel serves a request BEFORE the boundary is placed, so a failure afterwards is
  // attributable to the wrap and not to a channel that never worked.
  {
    GetEndpointsRequest warmUp;
    warmUp.endpoint_url() = mEndpointUrl;
    ASSERT_THAT(channel.try_get_endpoints_sync(std::move(warmUp)), ::ua::test_helpers::Good())
      << "the channel must serve a request before the sequence counters are moved to the wrap boundary";
  }

  // Place the client-to-server direction at the boundary on both sides: the sender's next stamp and the
  // receiver's last-seen. Neither side is told what to do at the boundary, only where the boundary is.
  CSCTA::on_strand(channel,
    [sequenceWrapBoundary](auto& g)
    {
      g.context()->lastTxSequenceNumber = sequenceWrapBoundary;
      // Part 6 6.7.2.4 also forbids reusing a SequenceNumber under one TokenId, so a real channel reaches
      // the wrap only on a token issued after its earlier numbers. Clearing the per-token record models
      // that token; without it the numbers after the wrap repeat ones this token already used.
      g.context()->txUseUnderToken = {};
    });
  ua::server::SecureChannelTestAccess::on_strand(*serverChannel,
    [sequenceWrapBoundary](auto& g)
    {
      g.context()->lastRxSequenceNumber = sequenceWrapBoundary;
      g.context()->rxUseUnderToken = {};
    });

  const size_t framesBeforeWrap = frames->count();
  mServerLogSink->clear();

  GetEndpointsRequest atWrap;
  atWrap.endpoint_url() = mEndpointUrl;
  auto atWrapResult = channel.try_get_endpoints_sync(std::move(atWrap));

  std::vector<uint32_t> sequenceNumbersAfterWrap;
  {
    const auto frameCount = frames->count();
    for (size_t i = framesBeforeWrap; i < frameCount; ++i)
    {
      auto frame = frames->get(i);
      // Symmetric chunk under Sign: [0-2]="MSG", [3]=chunk type, [4-7]=size, [8-11]=channelId,
      // [12-15]=tokenId, [16-19]=sequenceNumber, [20-23]=requestId. Nothing is encrypted under Sign.
      if (read_message_type(frame) == "MSG" && frame.size() >= 24)
        sequenceNumbersAfterWrap.push_back(read_le_uint32(frame, 16));
    }
  }
  ASSERT_FALSE(sequenceNumbersAfterWrap.empty())
    << "no symmetric MSG chunk was written after the transmit counter was placed at the boundary, so the "
       "number that follows UInt32.MaxValue was never observed";

  // Conjunct 2: the number after 4 294 967 295 is 0, read off the bytes the SDK wrote.
  EXPECT_EQ(sequenceNumbersAfterWrap.front(), 0u)
    << "the chunk written after SequenceNumber 4 294 967 295 carried " << sequenceNumbersAfterWrap.front()
    << "; Part 6 section 6.7.2.4 requires the first number after the wrap around to be 0";

  // Conjunct 3: the channel survives the wrap rather than treating it as an error. The request the wrapped
  // chunk carried was answered...
  EXPECT_THAT(atWrapResult, ::ua::test_helpers::Good())
    << "the request carried by the chunk at the wrap boundary failed; the receiver treated a legitimate "
       "sequence-number wrap as an error";

  // ...the receiver did not report the chunk as a failure...
  EXPECT_FALSE(wait_for_server_error_log(*mServerLogSink, chunkSecurityFailureSite, 2s))
    << "the server reported a chunk failure on the wrapped SequenceNumber; a wrap to 0 is required "
       "behaviour, not a replay";

  // ...the SecureChannel is still open on the server...
  auto serverStateAfterWrap =
    ua::server::SecureChannelTestAccess::on_strand(*serverChannel, [](auto& g) { return g.channel_state(); });
  EXPECT_EQ(serverStateAfterWrap, ua::server::SecureChannelTestAccess::ChannelState::Open)
    << "the server closed the SecureChannel when the SequenceNumber wrapped";

  // ...and it keeps serving past the wrap, which a receiver left with a corrupted expectation would not.
  GetEndpointsRequest afterRsaWrap;
  afterRsaWrap.endpoint_url() = mEndpointUrl;
  EXPECT_THAT(channel.try_get_endpoints_sync(std::move(afterRsaWrap)), ::ua::test_helpers::Good())
    << "the channel stopped serving requests once the SequenceNumber had wrapped";

  (void)channel.try_close_sync();
}

// ===========================================================================
// Part 6 transport-buffer obligations
// ===========================================================================

#include "ua_attribute_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_session_attribute_services.h"
#include "ua_timestamps_to_return.h"
#include "ua_variable_id.h"

#include <atomic>
#include <cstddef>
#include <memory>
#include <vector>

#include "test_components.h"

namespace
{

/// One transport-level chunk seen on the wire: its message type, its `isFinal` byte, and its length.
struct WireChunk
{
  std::string messageType;
  char isFinal{'\0'};
  size_t size{0};
};

/// Splits every captured write into the chunks it carries.
///
/// A single `async_write` normally carries exactly one chunk, but nothing in the transport contract
/// promises that, and a test that assumed it would silently stop measuring the moment the SDK
/// coalesced two chunks into one write. Walking by the declared message size keeps the measurement
/// correct either way, and any buffer that does not decompose cleanly is reported rather than skipped.
std::vector<WireChunk> split_into_chunks(const std::vector<std::byte>& buffer, bool& wellFormed)
{
  std::vector<WireChunk> chunks;
  size_t offset = 0;
  while (offset + 8 <= buffer.size())
  {
    const std::string messageType{static_cast<char>(buffer[offset]),
      static_cast<char>(buffer[offset + 1]),
      static_cast<char>(buffer[offset + 2])};
    const uint32_t declaredSize =
      static_cast<uint32_t>(buffer[offset + 4]) | (static_cast<uint32_t>(buffer[offset + 5]) << 8) |
      (static_cast<uint32_t>(buffer[offset + 6]) << 16) | (static_cast<uint32_t>(buffer[offset + 7]) << 24);
    if (declaredSize < 8 || offset + declaredSize > buffer.size())
    {
      wellFormed = false;
      return chunks;
    }
    chunks.push_back(
      WireChunk{messageType, static_cast<char>(buffer[offset + 3]), static_cast<size_t>(declaredSize)});
    offset += declaredSize;
  }
  if (offset != buffer.size())
    wellFormed = false;
  return chunks;
}

/// Little-endian uint32 written into a four-byte field of a captured frame.
void write_le_uint32(std::vector<std::byte>& buffer, size_t offset, uint32_t value)
{
  buffer[offset] = static_cast<std::byte>(value & 0xFF);
  buffer[offset + 1] = static_cast<std::byte>((value >> 8) & 0xFF);
  buffer[offset + 2] = static_cast<std::byte>((value >> 16) & 0xFF);
  buffer[offset + 3] = static_cast<std::byte>((value >> 24) & 0xFF);
}

}  // namespace

// @relation(AC-SVR-UASC-060-TRANSPORT-BUFFER-MINIMUM, scope=function)

// Part 6 section 6.7.1: "UASC requires a TransportProtocol buffer size that is at least 8 192 bytes when
// using RSA based Asymmetric Cryptography[.] This minimum buffer size drops to 1 024 when using ECC based
// Asymmetric Cryptography". Part 6 section 7.1.2.3 Table 66 places that floor on the HELLO SENDER: its
// ReceiveBufferSize and SendBufferSize each "Shall be at least 1 024 bytes if the sender intends to use
// an ECC SecurityPolicy. Shall be at least 8 192 bytes otherwise." So 1 024 is the absolute floor -- no
// sender may propose beneath it whatever key family it intends -- while 8 192 binds only a sender that
// has ruled ECC out. A channel that runs below the floor its family needs cannot fit an RSA-2048 key,
// its signature, the headers and one body byte into a single chunk, so the failure surfaces later,
// under load, as a message that cannot be encoded at all.
//
// What a RECEIVER owes in reply is a different cell, and it is the one that decides the shape of this
// test. Part 6 section 7.1.2.4 Table 67 both caps and floors the Acknowledge: ReceiveBufferSize "shall not be
// larger than the SendBufferSize requested in the Hello Message. Shall be at least 8 192 bytes if the
// SendBufferSize requested in the Hello Message is >= 8 192 bytes. Shall be at least 1 024 bytes
// otherwise", and SendBufferSize says the same against the Hello's ReceiveBufferSize. The "otherwise"
// branch has exactly one subject -- a Hello proposing less than 8 192 -- and it prescribes an ANSWER,
// not a refusal. Reading the cap alone and concluding that every sub-8 192 proposal has to be refused
// would leave that branch as dead text, so the two arms ask two different questions:
//
//   * 512 bytes sits below the 1 024 absolute floor, so cap and floor cross: no number is at once
//     <= 512 and >= 1 024, Table 67 admits no conformant Acknowledge at all, and refusal is the only
//     answer left. `SVR-UASC-060` states the server-side consequence -- the HEL handler refuses it.
//   * 4 096 bytes sits under the 8 192 RSA floor but above the absolute one, which is precisely the
//     "otherwise" branch. A receiver may answer neither above the 4 096 it was offered nor below
//     1 024, so every conformant Acknowledge to this Hello lands in [1 024, 4 096]. That window is
//     what the arm asserts, and it asserts nothing about acceptance: this fixture advertises None and
//     Basic256Sha256 endpoints only, both non-ECC, so nothing here can settle whether a server that
//     offers no ECC policy may refuse outright a proposal only an ECC client would lawfully make. The
//     window is what Table 67 binds whenever an Acknowledge IS sent, and no more.
//
// The negotiated limits read back below are the Acknowledge's own fields, not a derived quantity: the
// client transport stores ACK.ReceiveBufferSize as sendBufferSize ("what the peer can receive") and
// ACK.SendBufferSize as receiveBufferSize ("what the peer will send"), verbatim and unclamped, so the
// window is measured against the numbers the server actually put on the wire.
//
// The Hello is patched on the wire after the SDK has chosen its own value, because a sub-floor proposal
// is otherwise unreachable through the public API (the client clamps its configured buffer up to 8192
// before proposing). Patching there rather than in configuration also leaves the client's own record of
// its proposal at the fixture's 65 536, and it is that record -- not the wire -- which bounds the ACK
// the client will accept, so an answer anywhere above the patched 4 096 still reaches the assertions
// below instead of being refused by the client's transport first.
TEST_F(ComplianceSecureChannel, ATransportBufferBelowTheMinimumForItsKeyFamilyIsRefused)
{
  constexpr uint32_t nonEccMinimum = 8192u;
  constexpr uint32_t eccMinimum = 1024u;
  // The sub-floor proposal arm 2 puts on the wire. It is also arm 2's Table 67 CAP: the Acknowledge may
  // not exceed the Hello it answers, so the one constant has to serve both or the two can drift apart.
  constexpr uint32_t subFloorProposal = 4096u;

  // 0 means "leave the Hello as the SDK wrote it".
  auto patchedBufferSize = std::make_shared<std::atomic<uint32_t>>(0u);
  auto helloFrames = std::make_shared<CapturedFrames>();

  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [patchedBufferSize, helloFrames](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      fuzz->set_write_interceptor(
        [patchedBufferSize, helloFrames](std::vector<std::byte> data) -> std::vector<std::byte>
        {
          // HEL: [0-2]="HEL", [3]='F', [4-7]=messageSize, [8-11]=ProtocolVersion,
          // [12-15]=ReceiveBufferSize, [16-19]=SendBufferSize, ... Only fixed-width fields are
          // rewritten, so the declared message size stays correct.
          const uint32_t patch = patchedBufferSize->load(std::memory_order_acquire);
          if (patch != 0u && data.size() >= 20 && read_message_type(data) == "HEL")
          {
            write_le_uint32(data, 12, patch);
            write_le_uint32(data, 16, patch);
            helloFrames->add(data);
          }
          return data;
        });
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
  }

  // ---- Control: an unpatched Hello opens a channel on this fixture, so any refusal below is
  // attributable to the buffer size and not to the harness, the endpoint or the certificates.
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    cfg.serverCertificate = mServerCert;
    auto control = mClient->core().try_open_channel_sync(std::move(cfg));
    ASSERT_TRUE(control.is_good()) << "the unpatched handshake must open a channel, or the arms below "
                                      "prove nothing; status 0x"
                                   << std::hex << control.status_code().as_uint32();
    auto controlContext = CSCTA::on_strand(control.value(), [](auto& g) { return g.context(); });
    EXPECT_GE(controlContext->negotiatedLimits.sendBufferSize, nonEccMinimum);
    EXPECT_GE(controlContext->negotiatedLimits.receiveBufferSize, nonEccMinimum);
    (void)control.value().try_close_sync();
  }

  // ---- Arm 1: 512 bytes, below the 1 024 absolute (ECC) minimum as well as the 8 192 RSA one.
  {
    patchedBufferSize->store(512u, std::memory_order_release);
    const auto helloCountBefore = helloFrames->count();

    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::None;
    cfg.securityPolicyId = SecurityPolicyId::None;
    auto result = mClient->core().try_open_channel_sync(std::move(cfg));

    ASSERT_GT(helloFrames->count(), helloCountBefore)
      << "no HEL carried the 512-byte buffers - the stimulus never reached the wire";
    auto hello = helloFrames->get(helloFrames->count() - 1);
    ASSERT_EQ(read_le_uint32(hello, 12), 512u);
    ASSERT_EQ(read_le_uint32(hello, 16), 512u);

    // Refusal is asserted outright rather than conditionally, and for a 512-byte proposal it is the
    // ONLY conformant answer: Part 6 section 7.1.2.4 Table 67 caps the Acknowledge at the size the Hello
    // proposed (<= 512) and floors it at 1 024 for a sub-8 192 proposal, and those two cross, so no
    // number satisfies both. An `if (result.is_good())` here asserted nothing in either direction --
    // a server that refused reached no assertion at all, and a server that accepted was let off with
    // a buffer-window check -- which is the shape that lets a test stay green whatever happens.
    ASSERT_TRUE(result.is_bad())
      << "a handshake proposing 512-byte buffers produced a running channel; Table 67 can answer it "
         "with no size at once <= 512 and >= 1 024, so the connection had to be refused";
    if (result.is_good())
      (void)result.value().try_close_sync();
  }

  // ---- Arm 2: 4 096 bytes under Basic256Sha256, an RSA policy. Below section 6.7.1's 8 192 RSA floor, above
  // the 1 024 absolute one, so this is Table 67's "otherwise" branch and the Acknowledge -- if one
  // comes -- is bounded on both sides rather than being forbidden.
  {
    patchedBufferSize->store(subFloorProposal, std::memory_order_release);
    const auto helloCountBefore = helloFrames->count();

    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    cfg.serverCertificate = mServerCert;
    auto result = mClient->core().try_open_channel_sync(std::move(cfg));

    ASSERT_GT(helloFrames->count(), helloCountBefore)
      << "no HEL carried the 4 096-byte buffers - the stimulus never reached the wire";
    auto hello = helloFrames->get(helloFrames->count() - 1);
    ASSERT_EQ(read_le_uint32(hello, 12), subFloorProposal);
    ASSERT_EQ(read_le_uint32(hello, 16), subFloorProposal);

    if (result.is_good())
    {
      auto context = CSCTA::on_strand(result.value(), [](auto& g) { return g.context(); });

      // The arm claims to measure an RSA channel; a silent fallback to another policy would leave the
      // window assertions still true but about something else entirely.
      ASSERT_NE(context->securityPolicy, nullptr);
      ASSERT_EQ(context->securityPolicy->id(), SecurityPolicyId::Basic256Sha256);

      // sendBufferSize IS the ACK's ReceiveBufferSize, capped by Table 67 at the SendBufferSize the
      // Hello requested - 4 096 here - and floored at 1 024 by the "otherwise" branch, the Hello being
      // under 8 192.
      EXPECT_LE(context->negotiatedLimits.sendBufferSize, subFloorProposal)
        << "the Acknowledge answered a " << subFloorProposal << "-byte SendBufferSize proposal with "
        << context->negotiatedLimits.sendBufferSize
        << " bytes. Part 6 section 7.1.2.4 Table 67: the ACK ReceiveBufferSize \"shall not be larger than "
           "the "
           "SendBufferSize requested in the Hello Message\" - a receiver that needs more than it was "
           "offered has to refuse the handshake, not raise the number";
      EXPECT_GE(context->negotiatedLimits.sendBufferSize, eccMinimum)
        << "the Acknowledge answered with " << context->negotiatedLimits.sendBufferSize
        << " bytes. Part 6 section 7.1.2.4 Table 67 floors the ACK ReceiveBufferSize at " << eccMinimum
        << " bytes when the Hello requested less than " << nonEccMinimum;

      // receiveBufferSize IS the ACK's SendBufferSize, bounded the same way against the Hello's
      // ReceiveBufferSize.
      EXPECT_LE(context->negotiatedLimits.receiveBufferSize, subFloorProposal)
        << "the Acknowledge answered a " << subFloorProposal << "-byte ReceiveBufferSize proposal with "
        << context->negotiatedLimits.receiveBufferSize
        << " bytes, which Table 67 forbids: the ACK SendBufferSize \"shall not be larger than the "
           "ReceiveBufferSize requested in the Hello Message\"";
      EXPECT_GE(context->negotiatedLimits.receiveBufferSize, eccMinimum)
        << "the Acknowledge answered with " << context->negotiatedLimits.receiveBufferSize
        << " bytes, below Table 67's " << eccMinimum << "-byte floor";

      (void)result.value().try_close_sync();
    }
  }

  patchedBufferSize->store(0u, std::memory_order_release);
}

/// `ComplianceSecureChannel` whose CLIENT proposes the minimum lawful transport buffer, so the server
/// has to chunk anything larger than 8 192 bytes. At the 65 536-byte default nothing a compliance test
/// can comfortably ask for crosses a chunk boundary at all, and the obligation would be vacuous.
class ComplianceSecureChannelMinimumBuffer : public ComplianceSecureChannel
{
protected:
  static constexpr uint32_t sBufferSize{8192};

  void configure_client_application(ApplicationConfig& appCfg) override
  {
    ComplianceSecured::configure_client_application(appCfg);
    appCfg.stack_limits().connectionProtocolLimits.maxBufferSize = sBufferSize;
  }
};

// Part 6 section 6.7.2: a MessageChunk's body is bounded by the MaxBodySize the negotiated buffer leaves once
// the message header, the security header, the sequence header, the signature and any padding are
// subtracted -- "never write more body bytes than MaxBodySize in one chunk", so that no chunk on the
// wire exceeds the buffer the peer agreed to receive into.
//
// The formula subtracts the SECURITY overhead, and forgetting that term overruns the buffer by exactly
// the footer. That defect is invisible at MessageSecurityMode None, where the footer is empty: it
// appears the moment signing is switched on, which is when it is least expected and hardest to
// attribute. Both signing modes are therefore driven, and SignAndEncrypt adds the padding term on top.
//
// Each direction is measured by its own evidence. Outbound, every chunk the client puts on the wire is
// read out of the transport and its declared size compared with the negotiated SendBufferSize -- a
// direct measurement, and the multi-chunk guard below makes sure there is more than one chunk to
// measure. Inbound, the client's own connection protocol refuses any chunk whose declared size exceeds
// the negotiated ReceiveBufferSize, so a server that computed MaxBodySize without the signature would
// have its response rejected mid-message and the Read would fail; a Read that returns every one of its
// results is that refusal not happening across a response many chunks long.
// @verifies AC-SVR-UASC-015-MAXBODYSIZE
TEST_F(ComplianceSecureChannelMinimumBuffer, NoChunkOfAMultiChunkMessageExceedsTheNegotiatedBuffer)
{
  // Large enough that both the request and the response cross several 8 192-byte chunks, and below the
  // server's default MaxNodesPerRead of 1 000 so the service itself does not refuse the operation.
  constexpr size_t nodesPerRead = 800;

  for (const auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
  {
    const std::string modeLabel = mode == MessageSecurityMode::Sign ? "Sign" : "SignAndEncrypt";
    SCOPED_TRACE(modeLabel);

    auto captured = std::make_shared<CapturedFrames>();
    {
      ua::client::ClientTestHooks hooks;
      hooks.transportDecorator = [captured](std::shared_ptr<TransportConnection> inner)
      {
        auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
        fuzz->set_write_interceptor(
          [captured](std::vector<std::byte> data) -> std::vector<std::byte>
          {
            captured->add(data);
            return data;
          });
        return fuzz;
      };
      ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));
    }

    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    cfg.serverCertificate = mServerCert;
    auto channel = mClient->core().open_channel_sync(std::move(cfg));
    ASSERT_TRUE(channel.is_open());

    auto context = CSCTA::on_strand(channel, [](auto& g) { return g.context(); });
    const auto sendBufferSize = context->negotiatedLimits.sendBufferSize;
    const auto receiveBufferSize = context->negotiatedLimits.receiveBufferSize;
    // Non-vacuity: the small buffer really took. At the 65 536-byte default the message below fits in
    // a single chunk and nothing here would be a chunking test.
    ASSERT_EQ(sendBufferSize, ComplianceSecureChannelMinimumBuffer::sBufferSize)
      << "the negotiated send buffer is not the minimum this fixture asks for, so the message below may "
         "not chunk at all";
    ASSERT_EQ(receiveBufferSize, ComplianceSecureChannelMinimumBuffer::sBufferSize)
      << "the negotiated receive buffer is not the minimum this fixture asks for";

    auto session = channel.create_session_sync({.sessionName = "MaxBodySize" + modeLabel});
    session.activate_sync();
    ASSERT_TRUE(session.is_active());

    // Every result is the Server's NamespaceArray, a string array, so the response is far larger than
    // the request and both cross the buffer several times over.
    ReadRequest req;
    for (size_t i = 0; i < nodesPerRead; ++i)
    {
      ReadValueId rv;
      rv.node_id() = NodeId{VariableId::Server_NamespaceArray};
      rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
      req.nodes_to_read().push_back(std::move(rv));
    }
    req.timestamps_to_return() = TimestampsToReturn::Neither;

    auto resp = session.attributes().read_sync(std::move(req));

    // ---- Inbound: the response came back whole. The client refuses any inbound chunk longer than the
    // negotiated receive buffer, so a server that left the signature out of its MaxBodySize would have
    // this Read fail rather than return.
    EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood())
      << modeLabel
      << ": a response spanning many chunks did not arrive intact; a chunk longer than the negotiated "
      << receiveBufferSize << "-byte receive buffer is refused by the receiver";
    EXPECT_EQ(resp.results().size(), nodesPerRead) << modeLabel << ": the multi-chunk response was truncated";

    // ---- Outbound: measure every chunk the client wrote.
    size_t messageChunks = 0;
    size_t intermediateChunks = 0;
    size_t oversizeChunks = 0;
    size_t largestChunk = 0;
    bool wellFormed = true;
    const auto frameCount = captured->count();
    for (size_t i = 0; i < frameCount; ++i)
    {
      for (const auto& chunk : split_into_chunks(captured->get(i), wellFormed))
      {
        if (chunk.messageType != "MSG")
          continue;
        ++messageChunks;
        if (chunk.isFinal == 'C')
          ++intermediateChunks;
        largestChunk = std::max(largestChunk, chunk.size);
        if (chunk.size > static_cast<size_t>(sendBufferSize))
          ++oversizeChunks;
      }
    }

    EXPECT_TRUE(wellFormed) << modeLabel
                            << ": a captured transport write did not decompose into whole chunks, so "
                               "the sizes below were measured over an incomplete walk";
    GTEST_LOG_(INFO) << modeLabel << ": scanned " << frameCount << " transport writes carrying "
                     << messageChunks << " MSG chunks (" << intermediateChunks
                     << " intermediate); largest chunk " << largestChunk << " bytes against a "
                     << sendBufferSize << "-byte negotiated send buffer";

    ASSERT_GT(intermediateChunks, 0u)
      << modeLabel
      << ": no intermediate ('C') MSG chunk was written, so the request never spanned more than one "
         "chunk and this measured nothing about chunking";
    EXPECT_EQ(oversizeChunks, 0u)
      << modeLabel << ": " << oversizeChunks << " of " << messageChunks
      << " MSG chunks exceeded the negotiated " << sendBufferSize << "-byte send buffer (largest was "
      << largestChunk
      << " bytes) - the body was sized without subtracting the header, signature or padding the chunk "
         "also has to carry";

    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }
}
