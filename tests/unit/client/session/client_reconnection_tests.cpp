// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_sec_pol_none.h"
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_x509_certificate.h"

// Test-only access to client session and secure channel internals.
#include "../sdk/implementation/client/session/ua_client_session_test_access.h"
#include "../sdk/implementation/client/secure_channel/ua_client_secure_channel_test_access.h"

#include <condition_variable>
#include <mutex>

using namespace ua;
using namespace ua::client;
using namespace std::chrono_literals;

namespace
{

// Minimal stub of X509Certificate for non-null SecurityInfo population.
class StubX509Cert : public X509Certificate
{
public:
  bool operator==(const X509Certificate&) const override
  {
    return false;
  }

  int version() const override
  {
    return 3;
  }

  std::string serial_number() const override
  {
    return "1";
  }

  ByteString signature() const override
  {
    return {};
  }

  std::string issuer() const override
  {
    return "";
  }

  std::string issuer_country() const override
  {
    return "";
  }

  std::string issuer_organization() const override
  {
    return "";
  }

  std::string issuer_organizational_unit() const override
  {
    return "";
  }

  std::string issuer_distinguished_name() const override
  {
    return "";
  }

  std::string issuer_state() const override
  {
    return "";
  }

  std::string issuer_common_name() const override
  {
    return "";
  }

  std::string issuer_domain_component() const override
  {
    return "";
  }

  std::string issuer_locality() const override
  {
    return "";
  }

  UtcTime validity_from() const override
  {
    return {};
  }

  UtcTime validity_to() const override
  {
    return {};
  }

  std::string subject() const override
  {
    return "";
  }

  std::string subject_country() const override
  {
    return "";
  }

  std::string subject_organization() const override
  {
    return "";
  }

  std::string subject_organizational_unit() const override
  {
    return "";
  }

  std::string subject_distinguished_name() const override
  {
    return "";
  }

  std::string subject_state() const override
  {
    return "";
  }

  std::string subject_common_name() const override
  {
    return "";
  }

  std::string subject_domain_component() const override
  {
    return "";
  }

  std::string subject_locality() const override
  {
    return "";
  }

  ByteString public_key() const override
  {
    return {};
  }

  size_t public_key_bit_length() const override
  {
    return 2048;
  }

  CertificateKeyAlgorithm key_algorithm() const override
  {
    return CertificateKeyAlgorithm::Rsa;
  }

  ByteString authority_key_identifier() const override
  {
    return {};
  }

  ByteString subject_key_identifier() const override
  {
    return {};
  }

  bool key_usage_digital_signature() const override
  {
    return true;
  }

  bool key_usage_non_repudiation() const override
  {
    return false;
  }

  bool key_usage_key_encipherment() const override
  {
    return true;
  }

  bool key_usage_data_encipherment() const override
  {
    return false;
  }

  bool key_usage_key_agreement() const override
  {
    return false;
  }

  bool key_usage_key_cert_sign() const override
  {
    return false;
  }

  bool key_usage_crl_sign() const override
  {
    return false;
  }

  bool key_usage_encipher_only() const override
  {
    return false;
  }

  bool key_usage_decipher_only() const override
  {
    return false;
  }

  std::vector<boost::asio::ip::address> san_ip_addresses() const override
  {
    return {};
  }

  std::vector<std::string> san_hostnames() const override
  {
    return {};
  }

  std::vector<std::string> san_uris() const override
  {
    return {};
  }

  bool basic_constraints_ca() const override
  {
    return false;
  }

  uint32_t basic_constraints_path_length() const override
  {
    return 0;
  }

  bool extended_key_usage_client_auth() const override
  {
    return true;
  }

  bool extended_key_usage_server_auth() const override
  {
    return false;
  }

  ByteString thumbprint() const override
  {
    return {};
  }

  ByteString der_encoding() const override
  {
    return ByteString{0x30, 0x82, 0x01};
  }

  bool issued_by(const X509Certificate&) const override
  {
    return false;
  }

  bool issuer_of(const X509Certificate&) const override
  {
    return false;
  }

  bool self_signed() const override
  {
    return true;
  }

  CertificateSignatureAlgorithm signature_algorithm() const override
  {
    return CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  }
};

// Minimal stub of AsymmetricKeyPair for non-null SecurityInfo population.
class StubKeyPair : public AsymmetricKeyPair
{
public:
  CertificateKeyAlgorithm algorithm() const override
  {
    return CertificateKeyAlgorithm::Rsa;
  }

  ByteString public_key_der() const override
  {
    return ByteString{uint8_t{0x01}};
  }

  ByteString private_key_pem() const override
  {
    return ByteString{uint8_t{0x02}};
  }
};

class FakeReconnChannelDeps : public SecureChannelDependencies
{
public:
  explicit FakeReconnChannelDeps(boost::asio::any_io_executor ex)
    : mExecutor(ex), mAppCfg(ApplicationConfig::load_default())
  {}

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  shared_ptr<const Crypto> crypto() override
  {
    return nullptr;
  }

  shared_ptr<CertificateStore> certificate_store() override
  {
    return nullptr;
  }

  const ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  StructureFactory& structure_factory() override
  {
    return mFactory;
  }

  Logger logger() override
  {
    return {};
  }

  uint32_t service_timeout_ms() override
  {
    return 10000;
  }

  uint32_t default_return_diagnostics() override
  {
    return 0;
  }

private:
  boost::asio::any_io_executor mExecutor;
  ApplicationConfig mAppCfg;
  StructureFactory mFactory;
};

class FakeReconnSessionDeps : public SessionDependencies
{
public:
  explicit FakeReconnSessionDeps(boost::asio::any_io_executor ex)
    : mExecutor(ex), mAppCfg(ApplicationConfig::load_default())
  {}

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  shared_ptr<const Crypto> crypto() override
  {
    return nullptr;
  }

  shared_ptr<CertificateStore> certificate_store() override
  {
    return nullptr;
  }

  const ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  StructureFactory& structure_factory() override
  {
    return mFactory;
  }

  Logger logger() override
  {
    return {};
  }

  uint32_t service_timeout_ms() override
  {
    return 10000;
  }

  uint32_t default_return_diagnostics() override
  {
    return 0;
  }

private:
  boost::asio::any_io_executor mExecutor;
  ApplicationConfig mAppCfg;
  StructureFactory mFactory;
};

using STA = SessionTestAccess;
using SS = STA::SessionState;

struct ReconnTestSetup
{
  std::shared_ptr<FakeReconnChannelDeps> channelDeps;
  std::shared_ptr<FakeReconnSessionDeps> sessionDeps;
  std::shared_ptr<SecureChannelImpl> channel;
  std::shared_ptr<SessionImpl> session;

  /// Drop every executor-pinned shared_ptr so a subsequent pool.join() drains.
  void release()
  {
    session.reset();
    channel.reset();
    sessionDeps.reset();
    channelDeps.reset();
  }

  static ReconnTestSetup create(boost::asio::any_io_executor ex)
  {
    ReconnTestSetup s;
    s.channelDeps = std::make_shared<FakeReconnChannelDeps>(ex);
    s.sessionDeps = std::make_shared<FakeReconnSessionDeps>(ex);

    s.channel = SecureChannelImpl::create(
      s.channelDeps,
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      SecureChannelImpl::Config{},
      [](VoidResult) {},
      [](VoidResult) {});

    SecureChannelTestAccess::on_strand(
      *s.channel, [](auto& g) { g.channel_state() = SecureChannelImpl::ChannelState::Open; });

    SessionImpl::SecurityInfo secInfo;
    secInfo.clientCertificate = std::make_shared<StubX509Cert>();
    secInfo.clientKeyPair = std::make_shared<StubKeyPair>();
    secInfo.securityPolicy = std::make_shared<SecPolNone>();
    secInfo.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;

    s.session = SessionImpl::create(
      s.sessionDeps,
      s.channel,
      SessionImpl::Config{},
      std::move(secInfo),
      [](VoidResult) {},
      [](VoidResult) {});

    return s;
  }

  void set_active_on_strand()
  {
    STA::on_strand(*session, [](auto& g) { g.set_session_active(); });
  }

  SS read_state_on_strand()
  {
    return STA::on_strand(*session, [](auto& g) { return g.session_state(); });
  }

  void inject_channel_error_sync(StatusCode status)
  {
    STA::on_strand(*session, [status](auto& g) { g.inject_channel_error(status); });
  }

  /// See client_session_tests.cpp::TestSessionSetup::cleanup_sync - same rationale.
  void cleanup_sync()
  {
    if (!session)
      return;
    SecureChannelTestAccess::on_strand(*channel,
      [](auto& g)
      {
        auto pending = std::move(g.pending_requests());
        g.pending_requests().clear();
        for (auto& [handle, callback] : pending)
        {
          callback(SecureChannelImpl::ServiceResponseResult{Status::BadConnectionClosed});
        }
      });
    auto state = read_state_on_strand();
    if (state != SS::Closed && state != SS::Idle)
    {
      inject_channel_error_sync(Status::BadConnectionClosed);
      inject_channel_error_sync(Status::BadConnectionClosed);
    }
    STA::strand_barrier(*session);
  }
};

}  // namespace

// =============================================================================
// CL-RECONN-001 #124: Reconnect creates new channel and activates session
// =============================================================================

TEST(ClientReconnectionTests, ReconnectCreatesNewChannelAndActivatesSession)
{
  // Spec: Part 4, 6.7 -- Client shall re-establish by creating a new SecureChannel
  // and activating the Session with ActivateSession (not CreateSession).
  // Reconnection is NOT yet implemented. This test asserts the required behavior:
  // after a transport disconnect, the session should NOT permanently close.
  boost::asio::thread_pool tp;
  auto setup = ReconnTestSetup::create(tp.get_executor());

  setup.set_active_on_strand();

  // Simulate transport disconnect.
  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_NE(state, SS::Closed) << "Reconnection should attempt re-activation, not permanent close";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-RECONN-002 #125: Same security policy and credentials for reconnect
// =============================================================================

TEST(ClientReconnectionTests, ReconnectUsesSameSecurityPolicyAndCredentials)
{
  // Spec: Part 4, 6.7 -- Same security policy, application cert, and user credential.
  // Not yet implemented. Verify security info is preserved after disconnect.
  boost::asio::thread_pool tp;
  auto setup = ReconnTestSetup::create(tp.get_executor());

  setup.set_active_on_strand();

  // Read security info before disconnect.
  auto secInfo = STA::on_strand(*setup.session, [](auto& g) { return g.security_info(); });

  // Simulate disconnect.
  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto secInfoAfter = STA::on_strand(*setup.session, [](auto& g) { return g.security_info(); });

  // Verify security info is preserved after disconnect.
  EXPECT_EQ(secInfo.messageSecurityMode, secInfoAfter.messageSecurityMode)
    << "Message security mode must be preserved across reconnect";
  EXPECT_EQ(secInfo.clientCertificate, secInfoAfter.clientCertificate)
    << "Client certificate must be preserved across reconnect";
  EXPECT_EQ(secInfo.clientKeyPair, secInfoAfter.clientKeyPair)
    << "Client key pair must be preserved across reconnect";
  EXPECT_EQ(secInfo.securityPolicy, secInfoAfter.securityPolicy)
    << "Security policy must be preserved across reconnect";

  auto state = setup.read_state_on_strand();
  EXPECT_NE(state, SS::Closed) << "Reconnection should attempt re-activation, not permanent close";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-RECONN-003 #126: Activate failure falls back to CreateSession
// =============================================================================

TEST(ClientReconnectionTests, ReconnectActivateFailureFallsBackToCreateSession)
{
  // Spec: Part 4, 6.7 -- Client shall only create a new Session if ActivateSession fails.
  // When implemented: inject BadSessionIdInvalid to ActivateSession, verify CreateSession sent.
  boost::asio::thread_pool tp;
  auto setup = ReconnTestSetup::create(tp.get_executor());

  setup.set_active_on_strand();
  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_NE(state, SS::Closed) << "Reconnection should attempt re-activation, not permanent close";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-RECONN-003 #127: Activate success does not create new session
// =============================================================================

TEST(ClientReconnectionTests, ReconnectActivateSuccessDoesNotCreateNewSession)
{
  // Spec: Part 4, 6.7 -- If ActivateSession succeeds, no CreateSession needed.
  // When implemented: verify no CreateSession when ActivateSession succeeds on new channel.
  boost::asio::thread_pool tp;
  auto setup = ReconnTestSetup::create(tp.get_executor());

  setup.set_active_on_strand();
  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_NE(state, SS::Closed) << "Reconnection should attempt re-activation, not permanent close";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-RECONN-004 #128: Republish loop after reconnect
// =============================================================================

TEST(ClientReconnectionTests, ReconnectRepublishesUntilBadMessageNotAvailable)
{
  // Spec: Part 4, 6.7 -- After reconnect, client shall call Republish in a loop.
  // Requires Subscription and Republish infrastructure.
  boost::asio::thread_pool tp;
  auto setup = ReconnTestSetup::create(tp.get_executor());

  setup.set_active_on_strand();
  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_NE(state, SS::Closed) << "Reconnection should attempt re-activation, not permanent close";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-RECONN-005 #129: Security failure triggers GetEndpoints
// =============================================================================

TEST(ClientReconnectionTests, SecurityFailureTriggersGetEndpoints)
{
  // Spec: Part 4, 6.7 -- On security failure, client shall use GetEndpoints.
  // When implemented: verify GetEndpoints was called after BadSecurityChecksFailed.
  boost::asio::thread_pool tp;
  auto setup = ReconnTestSetup::create(tp.get_executor());

  setup.set_active_on_strand();
  setup.inject_channel_error_sync(Status::BadSecurityChecksFailed);

  auto state = setup.read_state_on_strand();
  EXPECT_NE(state, SS::Closed) << "Security failure should trigger GetEndpoints, not permanent close";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}

// =============================================================================
// CL-RECONN-006 #130: Cert update creates new session + transfers subscriptions
// =============================================================================

TEST(ClientReconnectionTests, CertUpdateCreatesNewSessionAndTransfersSubscriptions)
{
  // Spec: Part 4, 6.7 -- If client cert updated, create new Session and transfer subscriptions.
  // Requires Subscription transfer infrastructure.
  boost::asio::thread_pool tp;
  auto setup = ReconnTestSetup::create(tp.get_executor());

  setup.set_active_on_strand();
  setup.inject_channel_error_sync(Status::BadConnectionClosed);

  auto state = setup.read_state_on_strand();
  EXPECT_NE(state, SS::Closed) << "Cert update should create new session, not permanent close";
  setup.cleanup_sync();
  setup.release();
  ::ua::test_utils::drain_with_timeout(tp);
}
