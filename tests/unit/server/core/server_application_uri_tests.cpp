// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "dev_factories.h"

#include <boost/asio/thread_pool.hpp>

#include <string>

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_crypto.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_server.h"
#include "ua_server_authentication.h"
#include "ua_server_config_bundle.h"
#include "ua_server_configuration.h"
#include "test_utilities.h"

#include "server_impl_test_access.h"
#include "server_test_access.h"
#include "ua_server_impl.h"
#include "ua_server_session.h"
#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

CreateConfig make_config(const std::string& applicationUri)
{
  CreateConfig config{.identity = ApplicationIdentity::load_default(),
    .application = ApplicationConfig::load_default(),
    .server = ServerConfig{}};
  config.application.application_description_part().applicationUri = applicationUri;
  return config;
}

}  // namespace

/// Server::create rejects an empty applicationUri.
///
/// The value is published as both `Server.ServerArray[0]` and the URI of the server's own namespace
/// (Part 5), so an empty one produces a server that starts and serves tier-0 clients while leaving both
/// non-conformant: a tier-1 `ua::client::Client` cannot bootstrap against it, and no client can address
/// its own nodes by namespace URI. The rejection has to happen at construction, because every later
/// symptom is remote from this cause.
class ServerApplicationUriTests : public ::testing::Test
{
protected:
  boost::asio::thread_pool mPool{1};

  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }
};

TEST_F(ServerApplicationUriTests, CreateRejectsEmptyApplicationUri)
{
  EXPECT_THROW(Server::create(mPool.get_executor(),
                 make_config(""),
                 ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}),
    ua::UaException);
}

// The rejection carries BadConfigurationError - the canonical configuration-error status - so a caller
// can tell a misconfiguration apart from a runtime failure without parsing the message.
TEST_F(ServerApplicationUriTests, RejectionCarriesBadConfigurationError)
{
  try
  {
    Server::create(mPool.get_executor(),
      make_config(""),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    FAIL() << "expected Server::create to reject an empty applicationUri";
  }
  catch (const ua::UaException& ex)
  {
    EXPECT_EQ(ex.status(), ua::Status::BadConfigurationError);
  }
}

// The diagnostic must name the field to set. A rejection that only says "invalid configuration" moves the
// work of locating the cause back onto the operator, which is the failure this check exists to prevent.
TEST_F(ServerApplicationUriTests, RejectionNamesTheField)
{
  try
  {
    Server::create(mPool.get_executor(),
      make_config(""),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    FAIL() << "expected Server::create to reject an empty applicationUri";
  }
  catch (const ua::UaException& ex)
  {
    const auto* detail = ex.detail();
    ASSERT_NE(detail, nullptr) << "the rejection must carry an ErrorDetail";
    EXPECT_NE(detail->summary.find("application_description_part().applicationUri"), std::string::npos)
      << "summary must name the field to set, was: " << detail->summary;
  }
}

// A configured URI is accepted, so the check rejects only the empty case and not the ordinary one.
TEST_F(ServerApplicationUriTests, CreateAcceptsAConfiguredApplicationUri)
{
  EXPECT_NO_THROW({
    auto server = Server::create(mPool.get_executor(),
      make_config("urn:test:reduktive:application-uri"),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    server.shutdown_sync();
  });
}

// The no-configuration overload supplies its own URI: it chooses the entire configuration, so an
// overload that always threw would be unusable rather than safe.
TEST_F(ServerApplicationUriTests, DefaultOverloadSuppliesItsOwnApplicationUri)
{
  auto server = ua::test_helpers::make_dev_server(mPool.get_executor());
  const auto& uri = server.config().application->application_description_part().applicationUri;
  EXPECT_FALSE(uri.empty());
  EXPECT_EQ(uri.rfind("urn:reduktive:opcua-sdk:", 0), 0U) << "was: " << uri;
  server.shutdown_sync();
}

// The authentication interval moved from the removed security hooks to ServerConfig (owner
// decision 1a); the value set there is the one the session layer holds the refusal for. Observed
// through the SessionDependencies interface the Session reads it from, on a real ServerImpl - not the
// server's own copy of the configuration, which would pass whatever the session layer is handed.
// @verifies AC-SVR-IDENT-004-AUTHN-TIMEOUT-FROM-CONFIGURATION
// @relation(AC-SVR-IDENT-004-AUTHN-TIMEOUT-FROM-CONFIGURATION, scope=function)
TEST_F(ServerApplicationUriTests, TheConfiguredAuthenticationIntervalReachesTheSessionLayer)
{
  auto config = make_config("urn:test:authn-timeout-wiring");
  config.server.authnTimeout = 275ms;
  auto server =
    Server::create(mPool.get_executor(), std::move(config), {.crypto = ua::test_helpers::test_crypto()});
  const auto sessionDependencies =
    ua::test_helpers::ServerImplTestAccess{ua::test_helpers::ServerTestAccess::impl(server)}
      .session_dependencies();
  ASSERT_NE(sessionDependencies, nullptr);
  EXPECT_EQ(sessionDependencies->server_configuration().authnTimeout, 275ms);

  auto defaults = Server::create(mPool.get_executor(),
    make_config("urn:test:authn-timeout-default"),
    {.crypto = ua::test_helpers::test_crypto()});
  const auto defaultSessionDependencies =
    ua::test_helpers::ServerImplTestAccess{ua::test_helpers::ServerTestAccess::impl(defaults)}
      .session_dependencies();
  ASSERT_NE(defaultSessionDependencies, nullptr);
  EXPECT_EQ(defaultSessionDependencies->server_configuration().authnTimeout, 1000ms)
    << "the control: the default is one second";
  server.shutdown_sync();
  defaults.shutdown_sync();
}

// @relation(AC-SVR-IDENT-004-FIXED-TIME, scope=function)
// @relation(AC-COMP-SVR-SESSION-AUTH-FLOW-03-INTERVAL-POSITIVE, scope=function)
TEST_F(ServerApplicationUriTests, AuthenticationIntervalMustBePositive)
{
  for (const auto rejectedTimeout : {-1ms, 0ms})
  {
    SCOPED_TRACE(rejectedTimeout.count());
    auto config = make_config("urn:test:authn-timeout");
    config.server.authnTimeout = rejectedTimeout;

    try
    {
      Server::create(mPool.get_executor(), std::move(config), {.crypto = ua::test_helpers::test_crypto()});
      FAIL() << "expected Server::create to reject a non-positive fixed interval";
    }
    catch (const UaException& ex)
    {
      EXPECT_EQ(ex.status(), Status::BadConfigurationError);
      const auto* detail = ex.detail();
      ASSERT_NE(detail, nullptr);
      EXPECT_EQ(detail->code, "InvalidAuthenticationTimeout");
      EXPECT_EQ(test_utils::error_context(detail, ContextKeys::actual.value()),
        std::to_string(rejectedTimeout.count()));
      EXPECT_EQ(test_utils::error_context(detail, ContextKeys::min.value()), "1");
    }
  }

  auto acceptedConfig = make_config("urn:test:authn-timeout");
  acceptedConfig.server.authnTimeout = 1ms;
  auto server = Server::create(
    mPool.get_executor(), std::move(acceptedConfig), {.crypto = ua::test_helpers::test_crypto()});
  server.shutdown_sync();
}

// OPC 10000-4 7.41.4 Table 193 / OPC 10000-6 6.8.3 (decision BR-15): a None endpoint whose user tokens are
// secured with Basic128Rsa15 needs one held certificate valid for that policy - not a certificate filed under
// that policy's own type. A 2048-bit RsaSha256 certificate is valid for Basic128Rsa15 (Part 7: RSA
// 1024-2048), so the start-up type check accepts it; a secured endpoint still requires its own type.
// Falsifiable: the former check counted the token policy's type as required and refused to start.
// @relation(AC-SVR-IDENT-008-A-NONE-ENDPOINT-CERTIFICATE-IS-VALID-FOR-EVERY-TOKEN-POLICY, scope=function)
TEST(ServerEndpointCertificates, ANoneEndpointNeedsNoCertificateOfEachTokenPolicysType)
{
  static const auto crypto = ua::create_default_crypto([]() { return ua::SecureString{"p"}; });
  ua::Crypto::SubjectAlternateName names;
  names.uris.push_back("urn:test:start-check");
  auto identity = crypto->try_create_self_signed_application_instance_certificate_sync(
    ua::Crypto::Name{.commonName = "Start check"},
    ua::DateTime{2050, 1, 1, 0, 0, 0},
    names,
    ua::CertificateType::RsaSha256Application,
    2048);
  ASSERT_TRUE(identity.is_good());
  ua::CertificateStore::ApplicationCertificate held;
  held.certificateType = ua::CertificateType::RsaSha256Application;
  held.certificate = identity.value().second;
  held.keys = identity.value().first;

  ua::server::ServerEndpointConfig none;
  none.name = "None";
  none.securityPolicyId = ua::SecurityPolicyId::None;
  none.messageSecurityMode = ua::MessageSecurityMode::None;
  none.userIdentityTokens.push_back(
    ua::server::create_user_token_policy(ua::UserTokenType::UserName, ua::SecurityPolicyId::Basic128Rsa15));
  EXPECT_NO_THROW(ua::test_helpers::ServerImplTestAccess::validate_endpoint_certificates({none}, {held}));

  ua::server::ServerEndpointConfig secured;
  secured.name = "Basic128Rsa15";
  secured.securityPolicyId = ua::SecurityPolicyId::Basic128Rsa15;
  secured.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  EXPECT_THROW(ua::test_helpers::ServerImplTestAccess::validate_endpoint_certificates({secured}, {held}),
    ua::UaException)
    << "control: a secured endpoint still needs a certificate of its own type";
}

namespace
{

// A held application certificate of `type`, self-signed, for the start-up type check.
ua::CertificateStore::ApplicationCertificate held_certificate(ua::CertificateType type)
{
  static const auto crypto = ua::create_default_crypto([]() { return ua::SecureString{"p"}; });
  ua::Crypto::SubjectAlternateName names;
  names.uris.push_back("urn:test:start-check");
  auto identity = crypto->try_create_self_signed_application_instance_certificate_sync(
    ua::Crypto::Name{.commonName = "Start check"}, ua::DateTime{2050, 1, 1, 0, 0, 0}, names, type, 2048);
  EXPECT_TRUE(identity.is_good());
  ua::CertificateStore::ApplicationCertificate held;
  held.certificateType = type;
  if (identity.is_good())
  {
    held.certificate = identity.value().second;
    held.keys = identity.value().first;
  }
  return held;
}

}  // namespace

// RSA_DH secures the channel with the application's RSA certificate (Part 6 6.9 Table 72: RSA keys of 2048 to
// 4096 bits) and agrees keys in a finite-field group, so an RSA_DH endpoint needs an RsaSha256Application
// certificate. Falsifiable both ways: an ECC certificate alone is refused, and the RSA certificate alone is
// enough. Each endpoint is checked with only an Anonymous token policy, so the endpoint's own policy is what
// requires the certificate, and with a UserName token policy of its own policy.
// @verifies AC-SVR-SCE-001-RSA-DH-NEEDS-AN-RSA-CERTIFICATE
TEST(ServerEndpointCertificates, AnRsaDhEndpointNeedsAnRsaCertificate)
{
  const auto rsa = held_certificate(ua::CertificateType::RsaSha256Application);
  const auto ecc = held_certificate(ua::CertificateType::EccNistP256Application);

  for (const auto policy : {ua::SecurityPolicyId::RsaDhAesGcm, ua::SecurityPolicyId::RsaDhChaChaPoly})
  {
    for (const bool userNameToken : {false, true})
    {
      SCOPED_TRACE(
        ::testing::Message() << static_cast<int>(policy) << (userNameToken ? " UserName" : " Anonymous"));
      ua::server::ServerEndpointConfig rsaDh;
      rsaDh.name = "RSA_DH";
      rsaDh.securityPolicyId = policy;
      rsaDh.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
      rsaDh.userIdentityTokens.push_back(
        ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
      if (userNameToken)
        rsaDh.userIdentityTokens.push_back(
          ua::server::create_user_token_policy(ua::UserTokenType::UserName, policy));
      EXPECT_NO_THROW(ua::test_helpers::ServerImplTestAccess::validate_endpoint_certificates({rsaDh}, {rsa}));
      try
      {
        ua::test_helpers::ServerImplTestAccess::validate_endpoint_certificates({rsaDh}, {ecc});
        ADD_FAILURE() << "an RSA_DH endpoint started with an ECC certificate only";
      }
      catch (const ua::UaException& error)
      {
        EXPECT_EQ(error.status(), ua::Status::BadConfigurationError);
        ASSERT_NE(error.detail(), nullptr);
        EXPECT_EQ(error.detail()->code, "MissingCertificates");
      }
    }
  }
}
