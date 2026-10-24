// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <future>
#include <thread>

#include "ua_crypto_types.h"
#include "ua_security_policy.h"

#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_default_namespace.h"
#include "ua_node.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_timestamps_to_return.h"
#include "ua_value_source.h"

#include "stubs.h"
#include "test_utilities.h"
#include "access_control_test_support.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

class SecurityLevelTest : public ::testing::Test
{};

// --- None / Invalid mode always returns 0 ---

// @relation(SVR-ECC-010, SVR-SECADMIN-012, scope=function)
TEST_F(SecurityLevelTest, NoneMode_ReturnsZero)
{
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::None, SecurityPolicyId::Basic256Sha256));
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::None, SecurityPolicyId::Aes256Sha256RsaPss));
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::None, SecurityPolicyId::EccCurve448ChaChaPoly));
}

TEST_F(SecurityLevelTest, InvalidMode_ReturnsZero)
{
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::Invalid, SecurityPolicyId::Basic256Sha256));
}

// --- Deprecated policies return 0 regardless of mode ---

// @relation(SVR-ECC-009, SVR-ECC-010, SVR-SECADMIN-013, scope=function)
TEST_F(SecurityLevelTest, DeprecatedPolicies_ReturnZero)
{
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::Basic128Rsa15));
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic128Rsa15));
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::Basic256));
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256));
}

// --- None / Invalid policy returns 0 ---

TEST_F(SecurityLevelTest, NonePolicyWithAuthenticatedMode_ReturnsZero)
{
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::None));
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::None));
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::Invalid));
}

// --- PubSub-only policies return 0 ---

TEST_F(SecurityLevelTest, PubSubPolicies_ReturnZero)
{
  EXPECT_EQ(0, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::PubSubAes128Ctr));
  EXPECT_EQ(
    0, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::PubSubAes256Ctr));
}

// --- Sign mode: expected values for each policy (decision D-7: Sign = 5 + 5 * tier) ---

TEST_F(SecurityLevelTest, Sign_Basic256Sha256)
{
  EXPECT_EQ(10, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256));
}

TEST_F(SecurityLevelTest, Sign_EccNistP256)
{
  EXPECT_EQ(25, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::EccNistP256AesGcm));
}

TEST_F(SecurityLevelTest, Sign_Aes128Sha256RsaOaep)
{
  EXPECT_EQ(15, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::Aes128Sha256RsaOaep));
}

TEST_F(SecurityLevelTest, Sign_EccBrainpoolP256r1)
{
  EXPECT_EQ(
    30, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::EccBrainpoolP256r1AesGcm));
}

TEST_F(SecurityLevelTest, Sign_EccCurve25519ChaChaPoly)
{
  EXPECT_EQ(35, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::EccCurve25519ChaChaPoly));
}

TEST_F(SecurityLevelTest, Sign_EccNistP384)
{
  EXPECT_EQ(40, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::EccNistP384AesGcm));
}

TEST_F(SecurityLevelTest, Sign_Aes256Sha256RsaPss)
{
  EXPECT_EQ(20, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::Aes256Sha256RsaPss));
}

TEST_F(SecurityLevelTest, Sign_EccBrainpoolP384r1)
{
  EXPECT_EQ(
    45, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::EccBrainpoolP384r1AesGcm));
}

TEST_F(SecurityLevelTest, Sign_EccCurve448ChaChaPoly)
{
  EXPECT_EQ(50, compute_security_level(MessageSecurityMode::Sign, SecurityPolicyId::EccCurve448ChaChaPoly));
}

// --- SignAndEncrypt mode: expected values for each policy (SignAndEncrypt = 50 + 5 * tier) ---

TEST_F(SecurityLevelTest, SignAndEncrypt_Basic256Sha256)
{
  EXPECT_EQ(
    55, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256));
}

TEST_F(SecurityLevelTest, SignAndEncrypt_EccNistP256)
{
  EXPECT_EQ(
    70, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::EccNistP256AesGcm));
}

TEST_F(SecurityLevelTest, SignAndEncrypt_Aes128Sha256RsaOaep)
{
  EXPECT_EQ(
    60, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes128Sha256RsaOaep));
}

TEST_F(SecurityLevelTest, SignAndEncrypt_EccBrainpoolP256r1)
{
  EXPECT_EQ(75,
    compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::EccBrainpoolP256r1AesGcm));
}

TEST_F(SecurityLevelTest, SignAndEncrypt_EccCurve25519ChaChaPoly)
{
  EXPECT_EQ(80,
    compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::EccCurve25519ChaChaPoly));
}

TEST_F(SecurityLevelTest, SignAndEncrypt_EccNistP384)
{
  EXPECT_EQ(
    85, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::EccNistP384AesGcm));
}

TEST_F(SecurityLevelTest, SignAndEncrypt_Aes256Sha256RsaPss)
{
  EXPECT_EQ(
    65, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Aes256Sha256RsaPss));
}

TEST_F(SecurityLevelTest, SignAndEncrypt_EccBrainpoolP384r1)
{
  EXPECT_EQ(90,
    compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::EccBrainpoolP384r1AesGcm));
}

TEST_F(SecurityLevelTest, SignAndEncrypt_EccCurve448ChaChaPoly)
{
  EXPECT_EQ(
    95, compute_security_level(MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::EccCurve448ChaChaPoly));
}

namespace
{

// Every secured policy with the level the D-7 table gives it in Sign and in SignAndEncrypt mode.
struct ExpectedLevel
{
  SecurityPolicyId policy;
  uint8_t sign;
  uint8_t signAndEncrypt;
};

constexpr ExpectedLevel expectedLevels[] = {
  {SecurityPolicyId::Basic256Sha256, 10, 55},
  {SecurityPolicyId::Aes128Sha256RsaOaep, 15, 60},
  {SecurityPolicyId::Aes256Sha256RsaPss, 20, 65},
  {SecurityPolicyId::EccNistP256AesGcm, 25, 70},
  {SecurityPolicyId::EccNistP256ChaChaPoly, 25, 70},
  {SecurityPolicyId::EccBrainpoolP256r1AesGcm, 30, 75},
  {SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly, 30, 75},
  {SecurityPolicyId::RsaDhAesGcm, 30, 75},
  {SecurityPolicyId::RsaDhChaChaPoly, 30, 75},
  {SecurityPolicyId::EccCurve25519AesGcm, 35, 80},
  {SecurityPolicyId::EccCurve25519ChaChaPoly, 35, 80},
  {SecurityPolicyId::EccNistP384AesGcm, 40, 85},
  {SecurityPolicyId::EccNistP384ChaChaPoly, 40, 85},
  {SecurityPolicyId::EccBrainpoolP384r1AesGcm, 45, 90},
  {SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly, 45, 90},
  {SecurityPolicyId::EccCurve448AesGcm, 50, 95},
  {SecurityPolicyId::EccCurve448ChaChaPoly, 50, 95},
};

uint8_t sign_level(SecurityPolicyId policy)
{
  return compute_security_level(MessageSecurityMode::Sign, policy);
}

}  // namespace

// Every secured policy, the fourteen with SecureChannelEnhancements included, takes the level of its tier.
// @verifies AC-SVR-SECADMIN-014-SECURITYLEVEL-FAMILY-RANKING-PLACES-BERNSTEIN-CU
TEST_F(SecurityLevelTest, EveryPolicyTakesTheLevelOfItsTier)
{
  for (const auto& expected : expectedLevels)
  {
    SCOPED_TRACE(static_cast<int>(expected.policy));
    EXPECT_EQ(compute_security_level(MessageSecurityMode::Sign, expected.policy), expected.sign);
    EXPECT_EQ(
      compute_security_level(MessageSecurityMode::SignAndEncrypt, expected.policy), expected.signAndEncrypt);
  }
}

// --- Structural invariants ---

// @relation(SVR-SECADMIN-012, scope=function)
TEST_F(SecurityLevelTest, SignAndEncryptAlwaysGreaterThanSign_ForSamePolicy)
{
  for (const auto& expected : expectedLevels)
  {
    auto signLevel = compute_security_level(MessageSecurityMode::Sign, expected.policy);
    auto encryptLevel = compute_security_level(MessageSecurityMode::SignAndEncrypt, expected.policy);
    EXPECT_GT(encryptLevel, signLevel)
      << "SignAndEncrypt must be > Sign for policy " << static_cast<int>(expected.policy);
  }
}

// Decision D-7: a policy with SecureChannelEnhancements outranks every policy without them, in both modes -
// the weakest enhanced policy (ECC_nistP256) above the strongest legacy one (Aes256_Sha256_RsaPss). The
// group sizes are asserted so the comparison cannot pass over an empty group.
// @verifies AC-SVR-SECADMIN-014-SECURITYLEVEL-FAMILY-RANKING-PLACES-BERNSTEIN-CU
TEST_F(SecurityLevelTest, EnhancedPoliciesRankAboveEveryLegacyPolicy)
{
  for (const auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
  {
    SCOPED_TRACE(static_cast<int>(mode));
    uint8_t strongestLegacy = 0;
    uint8_t weakestEnhanced = 255;
    size_t legacy = 0;
    size_t enhanced = 0;
    for (const auto& expected : expectedLevels)
    {
      const auto level = compute_security_level(mode, expected.policy);
      if (SecurityPolicy::create(expected.policy)->secure_channel_enhancements())
      {
        weakestEnhanced = std::min(weakestEnhanced, level);
        ++enhanced;
      }
      else
      {
        strongestLegacy = std::max(strongestLegacy, level);
        ++legacy;
      }
    }
    EXPECT_EQ(legacy, 3u);
    EXPECT_EQ(enhanced, 14u);
    EXPECT_GT(weakestEnhanced, strongestLegacy);
  }
}

// @verifies AC-SVR-SECADMIN-014-SECURITYLEVEL-FAMILY-RANKING-PLACES-BERNSTEIN-CU
TEST_F(SecurityLevelTest, NistCurvesRankedBelowTheirBrainpoolAndRsaDhPeers)
{
  // NIST curves are penalised one tier below their Brainpool and RSA_DH strength peers; Brainpool and RSA_DH
  // are peers.
  EXPECT_LT(
    sign_level(SecurityPolicyId::EccNistP256AesGcm), sign_level(SecurityPolicyId::EccBrainpoolP256r1AesGcm));
  EXPECT_LT(sign_level(SecurityPolicyId::EccNistP256AesGcm), sign_level(SecurityPolicyId::RsaDhAesGcm));
  EXPECT_EQ(
    sign_level(SecurityPolicyId::EccBrainpoolP256r1AesGcm), sign_level(SecurityPolicyId::RsaDhAesGcm));
  EXPECT_LT(
    sign_level(SecurityPolicyId::EccNistP384AesGcm), sign_level(SecurityPolicyId::EccBrainpoolP384r1AesGcm));
}

// @relation(SVR-ECC-010, SVR-SECADMIN-014, scope=function)
TEST_F(SecurityLevelTest, BernsteinCurvesRankedAboveRsaAndBrainpool)
{
  // Bernstein curves rank one tier above their Brainpool and RSA_DH peers, and above every legacy RSA policy.
  EXPECT_GT(
    sign_level(SecurityPolicyId::EccCurve25519ChaChaPoly), sign_level(SecurityPolicyId::Aes128Sha256RsaOaep));
  EXPECT_GT(sign_level(SecurityPolicyId::EccCurve25519ChaChaPoly),
    sign_level(SecurityPolicyId::EccBrainpoolP256r1AesGcm));
  EXPECT_GT(sign_level(SecurityPolicyId::EccCurve25519ChaChaPoly), sign_level(SecurityPolicyId::RsaDhAesGcm));
  EXPECT_GT(
    sign_level(SecurityPolicyId::EccCurve448ChaChaPoly), sign_level(SecurityPolicyId::Aes256Sha256RsaPss));
  EXPECT_GT(sign_level(SecurityPolicyId::EccCurve448ChaChaPoly),
    sign_level(SecurityPolicyId::EccBrainpoolP384r1AesGcm));
}

// @verifies AC-SVR-SECADMIN-014-SECURITYLEVEL-FAMILY-RANKING-PLACES-BERNSTEIN-CU
TEST_F(SecurityLevelTest, AesGcmAndChaChaPolyOfACurveRankEqual)
{
  const std::pair<SecurityPolicyId, SecurityPolicyId> pairs[] = {
    {SecurityPolicyId::EccNistP256AesGcm, SecurityPolicyId::EccNistP256ChaChaPoly},
    {SecurityPolicyId::EccNistP384AesGcm, SecurityPolicyId::EccNistP384ChaChaPoly},
    {SecurityPolicyId::EccBrainpoolP256r1AesGcm, SecurityPolicyId::EccBrainpoolP256r1ChaChaPoly},
    {SecurityPolicyId::EccBrainpoolP384r1AesGcm, SecurityPolicyId::EccBrainpoolP384r1ChaChaPoly},
    {SecurityPolicyId::EccCurve25519AesGcm, SecurityPolicyId::EccCurve25519ChaChaPoly},
    {SecurityPolicyId::EccCurve448AesGcm, SecurityPolicyId::EccCurve448ChaChaPoly},
    {SecurityPolicyId::RsaDhAesGcm, SecurityPolicyId::RsaDhChaChaPoly},
  };
  for (const auto mode : {MessageSecurityMode::Sign, MessageSecurityMode::SignAndEncrypt})
  {
    for (const auto& [aesGcm, chaChaPoly] : pairs)
      EXPECT_EQ(compute_security_level(mode, aesGcm), compute_security_level(mode, chaChaPoly))
        << static_cast<int>(aesGcm) << " / " << static_cast<int>(chaChaPoly);
  }
}

// @relation(SVR-SECADMIN-014, scope=function)
TEST_F(SecurityLevelTest, FullOrderingWithinSignMode)
{
  auto basic256Sha256 = sign_level(SecurityPolicyId::Basic256Sha256);
  auto aes128 = sign_level(SecurityPolicyId::Aes128Sha256RsaOaep);
  auto aes256 = sign_level(SecurityPolicyId::Aes256Sha256RsaPss);
  auto nistP256 = sign_level(SecurityPolicyId::EccNistP256AesGcm);
  auto brainpoolP256 = sign_level(SecurityPolicyId::EccBrainpoolP256r1AesGcm);
  auto curve25519 = sign_level(SecurityPolicyId::EccCurve25519ChaChaPoly);
  auto nistP384 = sign_level(SecurityPolicyId::EccNistP384AesGcm);
  auto brainpoolP384 = sign_level(SecurityPolicyId::EccBrainpoolP384r1AesGcm);
  auto curve448 = sign_level(SecurityPolicyId::EccCurve448ChaChaPoly);

  EXPECT_LT(basic256Sha256, aes128);
  EXPECT_LT(aes128, aes256);
  EXPECT_LT(aes256, nistP256);
  EXPECT_LT(nistP256, brainpoolP256);
  EXPECT_LT(brainpoolP256, curve25519);
  EXPECT_LT(curve25519, nistP384);
  EXPECT_LT(nistP384, brainpoolP384);
  EXPECT_LT(brainpoolP384, curve448);
}

// --- The channel security mode a Node's AccessRestrictions demand ---

namespace
{

// Session stub whose channel security mode is a construction parameter, so the same Read can be
// driven over a Sign-only and over a SignAndEncrypt channel. Mirrors the session stub in
// read_service_requirement_tests.cpp.
class ChannelModeSessionInfo final : public SessionInfo, public SessionSecurityContext
{
public:
  ChannelModeSessionInfo(boost::asio::any_io_executor ex, bool identityAvailable, MessageSecurityMode mode,
    SecurityPolicyId policy)
    : mExecutor(ex), mAppCfg(std::make_shared<const ApplicationConfig>(ApplicationConfig::load_default())),
      mAddressSpace(AddressSpace::create("urn:test", mExecutor))
  {
    auto security = std::make_shared<EndpointSecurityContext>();
    security->endpointPolicyId = "L/Secured";
    security->messageSecurityMode = mode;
    security->securityPolicyId = policy;
    mSecurity = std::move(security);

    auto user = std::make_shared<UserIdentity>();
    user->userId = "anonymous";
    user->displayName = "Anonymous";
    user->kind = UserTokenKind::Anonymous;
    mUser = std::move(user);

    if (identityAvailable)
    {
      mAccessIdentity = ua::test_helpers::configure_test_access(mAddressSpace, mUser, mSecurity);
    }
  }

  boost::asio::any_io_executor executor() const
  {
    return mExecutor;
  }

  AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ApplicationConfig& configuration() const override
  {
    return *mAppCfg;
  }

  const ServerConfig& server_configuration() const override
  {
    return serverCfg;
  }

  NodeId session_id() const override
  {
    return NodeId{1, Guid::create_and_generate()};
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mSecurity;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return mAccessIdentity;
  }

  DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return ua::server::detail::make_diagnostic_security_context(
      *mSecurity, *mUser, serverCfg.diagnosticPolicy);
  }

  Logger logger() const override
  {
    return {};
  }

  ServerConfig serverCfg;

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ApplicationConfig> mAppCfg;
  AddressSpace mAddressSpace;
  std::shared_ptr<const EndpointSecurityContext> mSecurity;
  std::shared_ptr<const UserIdentity> mUser;
  std::shared_ptr<const AccessIdentity> mAccessIdentity;
};

struct ChannelModeReadResult
{
  ReadResponse response;
  bool isServiceFault{false};
  StatusCode serviceResult;
};

ChannelModeReadResult run_read(
  std::shared_ptr<ChannelModeSessionInfo> si, boost::asio::any_io_executor ex, ReadRequest req)
{
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = AttributeServiceSet::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto status = fut.wait_for(2s);
  if (status != std::future_status::ready)
  {
    ADD_FAILURE() << "Read service timed out";
    return {};
  }

  auto resp = fut.get();
  auto* rr = dynamic_cast<ReadResponse*>(resp.second.get());
  if (rr)
    return {*rr, false, rr->response_header().service_result()};

  auto* sf = dynamic_cast<ServiceFault*>(resp.second.get());
  if (sf)
  {
    ChannelModeReadResult result;
    result.isServiceFault = true;
    result.serviceResult = sf->response_header().service_result();
    return result;
  }

  ADD_FAILURE() << "Unexpected response type";
  return {};
}

// A readable Variable backed by a real data source, carrying AccessRestrictions that demand an
// encrypted channel. The value is genuinely available, so a server that ignores the restriction
// would hand it back Good rather than refusing.
void install_encryption_required_variable(AddressSpace as)
{
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, 100u}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& variable = varResult.value();
  variable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  auto* source = variable->external_value_source();
  ASSERT_NE(source, nullptr);
  auto installed = source->set_value_source(make_value_source(
    [](const ValueSource::ReadContext& /*context*/,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        done)
    {
      DataValue dv;
      dv.value() = Variant{static_cast<int32_t>(42)};
      dv.source_timestamp() = DateTime::now();
      done(std::move(dv));
    }));
  ASSERT_TRUE(installed.is_good());

  auto node = as.find_node_sync(NodeId{1, 100u});
  AccessRestrictionType restrictions;
  restrictions.set(AccessRestrictionType::Bit::EncryptionRequired);
  node.set_access_restrictions(restrictions);
}

ReadRequest make_value_read()
{
  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = NodeId{1, 100u};
  rvid.attribute_id() = utils::to_underlying(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(rvid));
  return req;
}

}  // namespace

// Part 4 5.10.2.4 (Table 55) with Part 3 8.56 (Table 38): when a Node's AccessRestrictions declare
// EncryptionRequired, a Read of its Value Attribute over a channel that is not SignAndEncrypt is
// refused per-operation with Bad_SecurityModeInsufficient - the client's recovery is to reconnect
// at a stronger mode, not to re-authenticate. A plausible implementation reads "insufficient" as
// "unsecured" and tests only for MessageSecurityMode::None; a Sign-only channel is authenticated
// and integrity-protected but carries the Value in clear, so it slips through that test and the
// restricted Value is disclosed with Good. Sign-only is therefore the case that separates a real
// mode comparison from a None check, and the value must not come back with the refusal.
// @verifies AC-SVR-ATTR-READ-025-BAD-SECURITYMODEINSUFFICIENT
// @relation(AC-SVR-BASE-077-AUTHORISED-ENCRYPTED-ARRAY, scope=function)
TEST_F(SecurityLevelTest, ReadOfEncryptionRequiringAttributeOverSignOnlyChannelIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto signOnly = std::make_shared<ChannelModeSessionInfo>(
    ex, true, MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);
  install_encryption_required_variable(signOnly->address_space());

  auto refused = run_read(signOnly, ex, make_value_read());
  ASSERT_FALSE(refused.isServiceFault);
  ASSERT_EQ(refused.response.results().size(), 1u);
  ASSERT_TRUE(refused.response.results()[0].status().has_value());
  EXPECT_EQ(*refused.response.results()[0].status(), Status::BadSecurityModeInsufficient);
  // The refusal must withhold the protected Value, not report a status beside it.
  EXPECT_TRUE(refused.response.results()[0].value().empty());

  // Control: the identical Read over a SignAndEncrypt channel is not refused, so the refusal above
  // is attributable to the channel's security mode and not to the Node being unreadable.
  auto encrypted = std::make_shared<ChannelModeSessionInfo>(
    ex, true, MessageSecurityMode::SignAndEncrypt, SecurityPolicyId::Basic256Sha256);
  install_encryption_required_variable(encrypted->address_space());

  auto allowed = run_read(encrypted, ex, make_value_read());
  ASSERT_FALSE(allowed.isServiceFault);
  ASSERT_EQ(allowed.response.results().size(), 1u);
  const auto& allowedStatus = allowed.response.results()[0].status();
  EXPECT_FALSE(allowedStatus.has_value() && *allowedStatus == Status::BadSecurityModeInsufficient);
  EXPECT_FALSE(allowed.response.results()[0].value().empty());

  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

// A readable Variable carrying no AccessRestrictions, so nothing about the channel's security mode
// bears on it. Read alongside a restricted Node it shows whether the refusal was scoped to the
// operation that earned it.
void install_unrestricted_variable(AddressSpace as, uint32_t identifier)
{
  auto varResult = as.try_create_sync<VariableAccessor>(NodeId{1, identifier}, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  auto& variable = varResult.value();
  variable.set_access_level(
    AccessLevelType{static_cast<uint8_t>(1 << utils::to_underlying(AccessLevelType::Bit::CurrentRead))});

  auto* source = variable->external_value_source();
  ASSERT_NE(source, nullptr);
  auto installed = source->set_value_source(make_value_source(
    [](const ValueSource::ReadContext& /*context*/,
      const Node&,
      const ReadValueId&,
      std::function<void(DataValueResult)>
        done)
    {
      DataValue dv;
      dv.value() = Variant{static_cast<int32_t>(7)};
      dv.source_timestamp() = DateTime::now();
      done(std::move(dv));
    }));
  ASSERT_TRUE(installed.is_good());
}

ReadRequest make_two_value_read(uint32_t firstIdentifier, uint32_t secondIdentifier)
{
  ReadRequest req;
  req.request_header().request_handle() = 2;
  ReadValueId first;
  first.node_id() = NodeId{1, firstIdentifier};
  first.attribute_id() = utils::to_underlying(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(first));
  ReadValueId second;
  second.node_id() = NodeId{1, secondIdentifier};
  second.attribute_id() = utils::to_underlying(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(second));
  return req;
}

}  // namespace

// Part 4 5.10.2.4 Table 55 lists Bad_SecurityModeInsufficient among the *operation* results of Read,
// not among its service results: the Service itself succeeds and the code lands in the results entry
// for the Node that demanded the stronger channel. A plausible implementation notices the weak
// channel while validating the request and answers with a ServiceFault, or stops processing the
// remaining operations once one trips, and either way a client reading one restricted Node beside
// unrestricted ones loses results it is entitled to and cannot tell which Node needs reconnecting at
// a stronger mode. A single-operation Read cannot distinguish per-operation from per-request refusal
// at all, so the discrimination needs a mixed request over the Sign-only channel.
// @verifies AC-SVR-ATTR-READ-025-BAD-SECURITYMODEINSUFFICIENT
TEST_F(SecurityLevelTest, ReadRequiringEncryptionOverSignOnlyChannelIsRefusedAsThatOperationsResult)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();

  auto signOnly = std::make_shared<ChannelModeSessionInfo>(
    ex, true, MessageSecurityMode::Sign, SecurityPolicyId::Basic256Sha256);
  install_encryption_required_variable(signOnly->address_space());
  install_unrestricted_variable(signOnly->address_space(), 101u);

  auto result = run_read(signOnly, ex, make_two_value_read(100u, 101u));

  // The Service must complete: the refusal is the operation's, so it cannot be raised as a fault.
  ASSERT_FALSE(result.isServiceFault);
  EXPECT_TRUE(result.serviceResult.is_good());
  ASSERT_EQ(result.response.results().size(), 2u);

  // Operation 0 - the Node whose AccessRestrictions demand encryption - is refused with the code
  // that tells the client to reconnect at a stronger mode, and its protected Value is withheld.
  ASSERT_TRUE(result.response.results()[0].status().has_value());
  EXPECT_EQ(*result.response.results()[0].status(), Status::BadSecurityModeInsufficient);
  EXPECT_TRUE(result.response.results()[0].value().empty());

  // Operation 1 - unrestricted, in the same request over the same weak channel - is unaffected:
  // it keeps a good status and still returns its value.
  EXPECT_TRUE(
    !result.response.results()[1].status().has_value() || result.response.results()[1].status()->is_good());
  EXPECT_FALSE(result.response.results()[1].value().empty());

  ::ua::test_utils::drain_with_timeout(tp);
}
