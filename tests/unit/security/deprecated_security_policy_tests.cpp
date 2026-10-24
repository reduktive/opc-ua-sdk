// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Tests for server-level deprecated security policy enforcement.
///
/// Verifies:
/// 1. Server rejects deprecated endpoint by default.
/// 2. Server allows deprecated endpoint when AllowDeprecatedSecurityPolicies is set.
///
/// Per-policy is_deprecated() flag tests are in security_policy_parameterized_tests.cpp.

#include "ua_log_sink.h"
#include "ua_log_entry.h"
#include <algorithm>
#include <future>
#include <mutex>
#include <gtest/gtest.h>

#include "ua_security_policy.h"
#include "ua_server.h"
#include <boost/asio/thread_pool.hpp>
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;

// ---------------------------------------------------------------------------
// Server-level enforcement tests
// ---------------------------------------------------------------------------

TEST(DeprecatedSecurityPolicyTests, ServerRejectsDeprecatedEndpointByDefault)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  // Ensure deprecated policies are NOT allowed (the default).
  ASSERT_FALSE(cfg.application.allowDeprecatedSecurityPolicies);

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  ua::transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "0.0.0.0:0";
  const auto handle = server.listen_sync(std::move(bind), {});

  ServerEndpointConfig ep;
  ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ep.securityPolicyId = SecurityPolicyId::Basic256;
  ep.userIdentityTokens.push_back(create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

  EXPECT_THROW(
    {
      try
      {
        server.add_endpoint(handle, ep);
      }
      catch (const UaException& ex)
      {
        EXPECT_EQ(ex.status(), Status::BadSecurityPolicyRejected);
        throw;
      }
    },
    UaException);
  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(DeprecatedSecurityPolicyTests, ServerRejectsBasic128Rsa15EndpointByDefault)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  ua::transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "0.0.0.0:0";
  const auto handle = server.listen_sync(std::move(bind), {});

  ServerEndpointConfig ep;
  ep.messageSecurityMode = MessageSecurityMode::Sign;
  ep.securityPolicyId = SecurityPolicyId::Basic128Rsa15;
  ep.userIdentityTokens.push_back(create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

  EXPECT_THROW(server.add_endpoint(handle, ep), UaException);
  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(DeprecatedSecurityPolicyTests, ServerAllowsDeprecatedEndpointWhenOptedIn)
{
  boost::asio::thread_pool threadPool;
  auto appCfg = test_utils::create_test_config();
  appCfg.allowDeprecatedSecurityPolicies = true;

  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = std::move(appCfg),
    .server = ua::server::ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  ua::transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "0.0.0.0:0";
  const auto handle = server.listen_sync(std::move(bind), {});

  ServerEndpointConfig ep;
  ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ep.securityPolicyId = SecurityPolicyId::Basic256;
  ep.userIdentityTokens.push_back(create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

  EXPECT_NO_THROW(server.add_endpoint(handle, ep));

  // Verify endpoint was actually registered.
  auto endpoints = server.endpoints(handle);
  ASSERT_EQ(endpoints.size(), 1u);
  EXPECT_EQ(endpoints.front().securityPolicyId, SecurityPolicyId::Basic256);
  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(DeprecatedSecurityPolicyTests, ServerAcceptsModernPolicyByDefault)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};

  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});

  ua::transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "0.0.0.0:0";
  const auto handle = server.listen_sync(std::move(bind), {});

  ServerEndpointConfig ep;
  ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  ep.userIdentityTokens.push_back(create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

  EXPECT_NO_THROW(server.add_endpoint(handle, ep));
  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

namespace
{
ua::server::ServerConfig::ListenerConfig listener_with(ServerEndpointConfig endpoint)
{
  ua::server::ServerConfig::ListenerConfig listener;
  listener.name = "declared";
  listener.bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  listener.bind.address = "127.0.0.1:0";
  listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};
  listener.endpoints.push_back(std::move(endpoint));
  return listener;
}

ServerEndpointConfig deprecated_endpoint()
{
  ServerEndpointConfig ep;
  ep.name = "deprecated";
  ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ep.securityPolicyId = SecurityPolicyId::Basic256;
  ep.userIdentityTokens.push_back(create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  return ep;
}

ServerEndpointConfig insecure_endpoint()
{
  ServerEndpointConfig ep;
  ep.name = "insecure";
  ep.messageSecurityMode = MessageSecurityMode::None;
  ep.securityPolicyId = SecurityPolicyId::None;
  ep.userIdentityTokens.push_back(create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  return ep;
}

ua::server::ServerConfig::ReverseConnectTarget reverse_target_with(ServerEndpointConfig endpoint)
{
  ua::server::ServerConfig::ReverseConnectTarget target;
  target.name = "declared-reverse";
  target.clientApplicationUri = "urn:test:client";
  target.clientEndpointUrl = "opc.tcp://127.0.0.1:1";  // never dialled: the gate refuses first
  target.serverEndpointUrl = "opc.tcp://127.0.0.1:4840";
  target.endpoints.push_back(std::move(endpoint));
  return target;
}

struct CreateRefusal
{
  Status status{Status::Good};
  std::string code;  ///< the ErrorDetail code, empty when created
  std::string context;  ///< the ErrorDetail's context values joined, empty when created
  bool cause{false};  ///< whether the detail carries a cause
  std::string causeCode;  ///< the cause's ErrorDetail code, empty without one
};

CreateRefusal create_refusal(ua::server::CreateConfig cfg)
{
  boost::asio::thread_pool threadPool;
  try
  {
    auto server = Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    server.shutdown_sync();
    ::ua::test_utils::drain_with_timeout(threadPool);
    return CreateRefusal{};
  }
  catch (const UaException& ex)
  {
    ::ua::test_utils::drain_with_timeout(threadPool);
    CreateRefusal refusal{.status = ex.status()};
    if (const auto detail = ex.detail())
    {
      refusal.code = detail->code;
      for (const auto& item : detail->context)
        refusal.context += item.key + "=" + item.value + ";";
      refusal.cause = detail->cause != nullptr;
      if (detail->cause)
        refusal.causeCode = detail->cause->code;
    }
    return refusal;
  }
}
}  // namespace

// DEF-2: an endpoint declared on a listener in the configuration passes the same gates as one added
// at runtime through add_endpoint; the server fails to create rather than serving it or dropping it.
// @verifies AC-SVR-SECADMIN-070-CONFIGURED-ENDPOINTS-PASS-THE-SECURITY-GATES
TEST(DeprecatedSecurityPolicyTests, ServerRejectsDeprecatedEndpointDeclaredInListenerConfiguration)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  ASSERT_FALSE(cfg.application.allowDeprecatedSecurityPolicies);
  cfg.server.listeners().push_back(listener_with(deprecated_endpoint()));
  const auto refusal = create_refusal(std::move(cfg));
  EXPECT_EQ(refusal.status, Status::BadSecurityPolicyRejected);
  EXPECT_EQ(refusal.code, "ConfiguredEndpointRejected");
  EXPECT_NE(refusal.context.find("listener.name=declared"), std::string::npos) << refusal.context;
  EXPECT_NE(refusal.context.find("endpoint.name=deprecated"), std::string::npos) << refusal.context;
  EXPECT_TRUE(refusal.cause) << "the gate's own detail travels as the cause";
}

// @verifies AC-SVR-SECADMIN-070-CONFIGURED-ENDPOINTS-PASS-THE-SECURITY-GATES
TEST(DeprecatedSecurityPolicyTests, ServerRejectsInsecureEndpointDeclaredInListenerConfiguration)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  cfg.application.allowInsecureEndpoints = false;  // the test config opts in by default
  cfg.server.listeners().push_back(listener_with(insecure_endpoint()));
  const auto refusal = create_refusal(std::move(cfg));
  EXPECT_EQ(refusal.status, Status::BadSecurityModeRejected);
  EXPECT_EQ(refusal.code, "ConfiguredEndpointRejected");
}

// @verifies AC-SVR-SECADMIN-070-REVERSE-CONNECT-ENDPOINTS-PASS-THE-SECURITY-GATES
TEST(DeprecatedSecurityPolicyTests, ServerRejectsInsecureReverseConnectTargetEndpoint)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  cfg.application.allowInsecureEndpoints = false;
  cfg.server.reverseConnectTargets.push_back(reverse_target_with(insecure_endpoint()));
  const auto refusal = create_refusal(std::move(cfg));
  EXPECT_EQ(refusal.status, Status::BadSecurityModeRejected);
  EXPECT_NE(refusal.context.find("declared-reverse"), std::string::npos) << refusal.context;
}

// @verifies AC-SVR-SECADMIN-070-REVERSE-CONNECT-ENDPOINTS-PASS-THE-SECURITY-GATES
TEST(DeprecatedSecurityPolicyTests, RuntimeReverseConnectRejectsDeprecatedEndpoint)
{
  boost::asio::thread_pool threadPool;
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  ASSERT_FALSE(cfg.application.allowDeprecatedSecurityPolicies);
  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  const auto result = server.try_start_reverse_connect_sync(reverse_target_with(deprecated_endpoint()));
  ASSERT_TRUE(result.is_bad()) << "the runtime reverse-connect target must pass the gates first";
  EXPECT_EQ(result.status_code(), Status::BadSecurityPolicyRejected);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ReverseConnectEndpointRejected");
  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Control: with both opt-ins the same declarations are accepted, so the refusals above are the gates.
// @verifies AC-SVR-SECADMIN-070-CONFIGURED-ENDPOINTS-PASS-THE-SECURITY-GATES
TEST(DeprecatedSecurityPolicyTests, DeclaredEndpointsAreAcceptedWhenOptedIn)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  cfg.application.allowInsecureEndpoints = true;
  cfg.application.allowDeprecatedSecurityPolicies = true;
  cfg.server.listeners().push_back(listener_with(deprecated_endpoint()));
  cfg.server.reverseConnectTargets.push_back(reverse_target_with(insecure_endpoint()));
  EXPECT_EQ(create_refusal(std::move(cfg)).status, Status::Good);
}

namespace
{
ServerEndpointConfig modern_endpoint_with_deprecated_user_token_policy()
{
  ServerEndpointConfig ep;
  ep.name = "modern";
  ep.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  ep.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  ep.userIdentityTokens.push_back(create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  ep.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::UserName, SecurityPolicyId::Basic128Rsa15));
  return ep;
}
}  // namespace

// CRY-9: a UserTokenPolicy naming a deprecated SecurityPolicy of its own (the secret is then wrapped
// with RSA PKCS#1 v1.5) passes the same opt-in as the channel policy, on every path the gate runs.
// @verifies AC-SVR-SECADMIN-070-USER-TOKEN-POLICIES-PASS-THE-DEPRECATION-GATE
TEST(DeprecatedSecurityPolicyTests, AUserTokenPolicyNamingADeprecatedPolicyIsRefusedWithoutTheOptIn)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  ASSERT_FALSE(cfg.application.allowDeprecatedSecurityPolicies);
  cfg.server.listeners().push_back(listener_with(modern_endpoint_with_deprecated_user_token_policy()));
  const auto refusal = create_refusal(std::move(cfg));
  EXPECT_EQ(refusal.status, Status::BadSecurityPolicyRejected);
  EXPECT_EQ(refusal.code, "ConfiguredEndpointRejected");
  EXPECT_NE(refusal.context.find("endpoint.name=modern"), std::string::npos) << refusal.context;
  ASSERT_TRUE(refusal.cause) << "the gate's own detail travels as the cause";
  EXPECT_EQ(refusal.causeCode, "DeprecatedUserTokenSecurityPolicy");
}

// @verifies AC-SVR-SECADMIN-070-USER-TOKEN-POLICIES-PASS-THE-DEPRECATION-GATE
TEST(DeprecatedSecurityPolicyTests, AUserTokenPolicyNamingADeprecatedPolicyIsAcceptedWithTheOptIn)
{
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  cfg.application.allowDeprecatedSecurityPolicies = true;
  cfg.server.listeners().push_back(listener_with(modern_endpoint_with_deprecated_user_token_policy()));
  EXPECT_EQ(create_refusal(std::move(cfg)).status, Status::Good);
}

namespace
{
/// Collects the warnings a server logs, for the start-time configuration checks.
class WarningCollector final : public LogSink
{
public:
  void log(const LogEntry& entry) override
  {
    if (entry.level != LogLevel::Warning)
      return;
    const std::lock_guard lock(mMutex);
    mWarnings.push_back(entry.message);
  }

  bool saw(std::string_view fragment) const
  {
    const std::lock_guard lock(mMutex);
    return std::any_of(mWarnings.begin(),
      mWarnings.end(),
      [fragment](const std::string& message) { return message.find(fragment) != std::string::npos; });
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::string> mWarnings;
};

struct StartObservation
{
  bool started{false};
  bool warned{false};
};

StartObservation start_and_observe(
  std::optional<uint32_t> maxConnections, std::optional<uint32_t> maxSecureChannels)
{
  boost::asio::thread_pool threadPool;
  auto sink = std::make_shared<WarningCollector>();
  ua::server::CreateConfig cfg{.identity = ua::ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ua::server::ServerConfig{}};
  cfg.server.maxConnections = maxConnections;
  cfg.server.maxSecureChannels = maxSecureChannels;
  auto server = Server::create(threadPool.get_executor(),
    std::move(cfg),
    ua::server::ServerComponents{
      .crypto = ua::test_helpers::test_crypto(), .logSink = sink, .logLevel = LogLevel::Debug});
  std::promise<VoidResult> started;
  auto startedFuture = started.get_future();
  server.start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
  StartObservation observation;
  observation.started = startedFuture.wait_for(std::chrono::seconds{5}) == std::future_status::ready &&
                        startedFuture.get().is_good();
  observation.warned = sink->saw("secure-channel eviction gate is unreachable");
  server.shutdown_sync();
  ::ua::test_utils::drain_with_timeout(threadPool);
  return observation;
}
}  // namespace

// DEF-3: MaxConnections at or below MaxSecureChannels makes the Part 4 5.5.2.1 eviction unreachable;
// start() says so (a warning, since some deployments choose the connection limit as their refusal
// point on purpose). The defaults (200/100) do not warn.
// @verifies AC-SVR-SC-002-EVICTION-REACHABLE-AT-DEFAULTS
TEST(ServerStartWarnings, InvertedAdmissionLimitsLogAWarningAtStart)
{
  const auto equal = start_and_observe(1, 1);
  ASSERT_TRUE(equal.started);
  EXPECT_TRUE(equal.warned) << "equal limits: the evicting gate is never reached";
  const auto inverted = start_and_observe(5, 10);
  ASSERT_TRUE(inverted.started);
  EXPECT_TRUE(inverted.warned) << "inverted limits";
}

// @verifies AC-SVR-SC-002-EVICTION-REACHABLE-AT-DEFAULTS
TEST(ServerStartWarnings, DefaultAdmissionLimitsDoNotWarn)
{
  const auto defaults = start_and_observe(
    ua::server::ServerConfig{}.maxConnections, ua::server::ServerConfig{}.maxSecureChannels);
  ASSERT_TRUE(defaults.started) << "the control proves nothing unless the server actually started";
  EXPECT_FALSE(defaults.warned) << "200/100 keeps the eviction reachable, so nothing to warn about";
}
