// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Public tier-2 integration coverage for CL-SECADMIN-011.
///
/// A real in-tree server offers deprecated Basic128Rsa15 only after explicitly opting in. Tests enter
/// through managed Client::try_connect_sync (TCP -> OPN -> CreateSession -> ActivateSession -> bootstrap):
/// default client policy rejects before the wire path, while an explicitly opted-in Client completes the
/// same real connection.

#include "compliance_helpers.h"

#include "ua_connection.h"
#include "ua_connection_config.h"

namespace
{

class ClientSecurityPolicy : public ComplianceSecured
{
protected:
  void configure_secured_server(ApplicationConfig& appConfig) override
  {
    appConfig.allowDeprecatedSecurityPolicies = true;
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    // The legacy RSA policies select the RsaMinApplication store slot. Reuse the fixture's same conformant
    // RSA certificate/key under that policy slot; the certificate identity itself is unchanged.
    auto serverLegacyCertificate =
      mServerCertStore->get_application_certificate_sync(CertificateType::RsaSha256Application);
    serverLegacyCertificate.certificateType = CertificateType::RsaMinApplication;
    mServerCertStore->add_to_application_certificates_sync(std::move(serverLegacyCertificate));
    auto clientLegacyCertificate =
      mClientCertStore->get_application_certificate_sync(CertificateType::RsaSha256Application);
    clientLegacyCertificate.certificateType = CertificateType::RsaMinApplication;
    mClientCertStore->add_to_application_certificates_sync(std::move(clientLegacyCertificate));

    ServerEndpointConfig legacyEndpoint;
    legacyEndpoint.name = "Basic128Rsa15_SignAndEncrypt";
    legacyEndpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    legacyEndpoint.securityPolicyId = SecurityPolicyId::Basic128Rsa15;
    legacyEndpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(legacyEndpoint));

    ServerEndpointConfig legacyBasic256Endpoint;
    legacyBasic256Endpoint.name = "Basic256_SignAndEncrypt";
    legacyBasic256Endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    legacyBasic256Endpoint.securityPolicyId = SecurityPolicyId::Basic256;
    legacyBasic256Endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(legacyBasic256Endpoint));
  }

  ConnectionConfig legacy_connection_config(SecurityPolicyId policyId = SecurityPolicyId::Basic128Rsa15) const
  {
    ConnectionConfig config;
    config.endpointUrl = mEndpointUrl;
    config.securityMode = MessageSecurityMode::SignAndEncrypt;
    config.securityPolicyId = policyId;
    config.serverCertificate = mServerCert;
    config.reconnect = std::nullopt;
    return config;
  }
};

// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST_F(ClientSecurityPolicy, RejectsBasic128Rsa15ByDefault)
{
  auto result = mClient->try_connect_sync(legacy_connection_config());

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
  ASSERT_TRUE(result.shared_detail());
  const auto detail = ua::to_string(*result.shared_detail());
  EXPECT_NE(detail.find("Basic128Rsa15"), std::string::npos);
  EXPECT_NE(detail.find("AllowDeprecatedSecurityPolicies"), std::string::npos);
}

// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST_F(ClientSecurityPolicy, RejectsBasic256ByDefault)
{
  auto result = mClient->try_connect_sync(legacy_connection_config(SecurityPolicyId::Basic256));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityPolicyRejected});
  ASSERT_TRUE(result.shared_detail());
  EXPECT_NE(ua::to_string(*result.shared_detail()).find("Basic256"), std::string::npos);
}

// @verifies CL-SECADMIN-011
// @relation(CL-SECADMIN-011, scope=function)
TEST_F(ClientSecurityPolicy, AcceptsBasic128Rsa15WithExplicitOptIn)
{
  auto clientAppConfig = ua::test_utils::create_test_config();
  configure_client_application(clientAppConfig);
  clientAppConfig.allowDeprecatedSecurityPolicies = true;
  client::CreateConfig clientConfig{
    .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppConfig)};
  Client legacyClient = Client::create(mClientThreadPool.executor(),
    std::move(clientConfig),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = mClientCertStore,
      .logSink = test_log_sink(),
      .logLevel = LogLevel::Debug});

  auto result = legacyClient.try_connect_sync(legacy_connection_config());

  ASSERT_TRUE(result.is_good()) << ua::to_string(result.status_code());
  auto connection = std::move(result).value();
  EXPECT_TRUE(connection.try_close_sync().is_good());
}

}  // namespace
