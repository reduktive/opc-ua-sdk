// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief C13 (completeness review 2026-10-02): the client validating a server no conforming SDK server can
///        impersonate, driven by the MisbehavingServer fixture (tooling/fuzzer).
///
///   - Client-side Security Policy Check per policy family: the server presents a certificate violating the
///     endpoint policy (RSA key below the minimum, a disallowed signature algorithm, an ECC key on the wrong
///     curve, a disallowed ECDSA hash); the client API reports Bad_CertificatePolicyCheckFailed. An SDK
///     server refuses to start with such a certificate (approved decision F), so the fixture installs it
///     through its CertificateScenario, which bypasses that startup check (fixture-only seam).
///   - OPN vs CreateSession certificate (OPC 10000-4 5.6.2.2, decision 26):
///   CreateSessionResponse.serverCertificate
///     rewritten to ANOTHER leaf -> the client refuses with Bad_SecurityChecksFailed; rewritten to the SAME
///     leaf followed by a chain -> the client connects.
///
/// Expected codes come from the oracle in certificate_validation_integration_fixture.h (no SDK calls).
/// TIER: Client::try_connect_sync (tier 2).

#include "certificate_validation_integration_fixture.h"
#include "misbehaving_server.h"

#include "ua_create_session_response.h"

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::test_helpers;
using namespace ua::test_helpers::certificate_validation;

namespace
{

/// One RSA and one ECC configuration: the controls and the OPN/CreateSession rows.
std::vector<MatrixParam> control_params()
{
  return {MatrixParam{.policy = SecurityPolicyId::Basic256Sha256,
            .mode = MessageSecurityMode::SignAndEncrypt,
            .certificateCase = CertificateCase::Valid},
    MatrixParam{.policy = SecurityPolicyId::EccNistP256AesGcm,
      .mode = MessageSecurityMode::SignAndEncrypt,
      .certificateCase = CertificateCase::Valid}};
}

/// One row per policy family rule: RSA below the minimum (PolicyKeyLength under Basic256Sha256), RSA SHA-1
/// (PolicySignature under Basic256Sha256), ECC wrong curve (PolicyKeyLength under EccNistP256), ECDSA hash
/// not matching the signer's curve (PolicySignature under EccNistP256).
std::vector<MatrixParam> policy_family_params()
{
  std::vector<MatrixParam> params;
  for (const auto& control : control_params())
  {
    for (auto certificateCase : {CertificateCase::PolicyKeyLength, CertificateCase::PolicySignature})
      params.push_back(
        MatrixParam{.policy = control.policy, .mode = control.mode, .certificateCase = certificateCase});
  }
  return params;
}

class CertificateValidationMisbehavingServer : public ::testing::TestWithParam<MatrixParam>
{
protected:
  void SetUp() override
  {}

  void TearDown() override
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
    mConnection.reset();
    mClient.reset();
    mServer.reset();
    mClientStore.reset();
  }

  /// Starts a MisbehavingServer presenting @p serverOwn on the parameter's endpoint, trusting the family
  /// client certificate, and a client trusting the family PKI.
  void start(const LeafMaterial& serverOwn)
  {
    const auto& param = GetParam();
    auto& pki = shared_pki();
    auto& cache = MatrixCache::instance();
    mServer = std::make_unique<MisbehavingServer>(MisbehavingServer::Config{
      .secureChannelMinimumLifetime = std::chrono::milliseconds{2000},
      .certificateScenario = MisbehavingServer::CertificateScenario{.certificate = serverOwn.certificate,
        .keys = serverOwn.keys,
        .issuerCertificates = serverOwn.presentedIssuers,
        .certificateType = application_certificate_type(param.policy),
        .securedPolicy = param.policy,
        .securedMode = param.mode,
        // The client presents the family's self-signed client certificate, which the server trusts
        // directly: a trusted self-signed certificate needs no issuer and no CRL (revocation is checked
        // by default), and this fixture is about the CLIENT's checks of the server certificate.
        .trustedCertificates = {pki.leaf(param.policy, CertificateCase::Untrusted, Role::Client).certificate},
        .applicationUri = serverUri}});
    mClientStore = make_store(cache.new_directory("c13_client"),
      cache.client_pool().executor(),
      pki.crypto(),
      validation_options_for(CertificateCase::Valid),
      pki.trust_material(family_of(param.policy)),
      &pki.leaf(param.policy, CertificateCase::Untrusted, Role::Client),
      application_certificate_type(param.policy));
    mClient.emplace(make_matrix_client(cache.client_pool(), pki.crypto(), mClientStore));
  }

  ConnectResult connect()
  {
    // The fixture advertises 127.0.0.1; the certificates name "localhost" (host-name check, Table 106 step
    // 8).
    std::string url = mServer->endpoint_url_sign_encrypt();
    const auto loopback = url.find("127.0.0.1");
    if (loopback != std::string::npos)
      url.replace(loopback, std::string_view{"127.0.0.1"}.size(), "localhost");
    auto result =
      reported(mClient->try_connect_sync(matrix_connection_config(url, GetParam().policy, GetParam().mode)));
    if (result.is_good())
      mConnection.emplace(std::move(result).value());
    return result;
  }

  /// Rewrites every CreateSessionResponse.serverCertificate to @p field.
  void rewrite_create_session_certificate(ByteString field)
  {
    mServer->set_response_mutator(
      [field = std::move(field)](ua::Response& response)
      {
        if (auto* createSession = dynamic_cast<ua::CreateSessionResponse*>(response.second.get()))
          createSession->server_certificate() = field;
      });
  }

  const LeafMaterial& valid_server() const
  {
    return shared_pki().leaf(GetParam().policy, CertificateCase::Valid, Role::Server);
  }

  std::unique_ptr<MisbehavingServer> mServer;
  std::shared_ptr<CertificateStore> mClientStore;
  std::optional<client::Client> mClient;
  std::optional<client::Connection> mConnection;
};

class CertificateValidationClientPolicyFamilies : public CertificateValidationMisbehavingServer
{};

class CertificateValidationClientPolicyControl : public CertificateValidationMisbehavingServer
{};

class CertificateValidationOpnCreateSessionMismatch : public CertificateValidationMisbehavingServer
{};

// A server certificate violating the endpoint policy is refused by the client with
// Bad_CertificatePolicyCheckFailed (Table 106 step 4, not suppressible: owner decision 22.3).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-131-CLIENT-POLICY-FAMILIES, scope=function)
TEST_P(CertificateValidationClientPolicyFamilies, TheClientRefusesAPolicyViolatingServerCertificate)
{
  start(shared_pki().leaf(GetParam().policy, GetParam().certificateCase, Role::Server));
  auto result = connect();
  ASSERT_TRUE(result.is_bad()) << "a policy-violating server certificate must not connect";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificatePolicyCheckFailed})
    << "got 0x" << std::hex << result.status_code().as_uint32();
}

// Control: the same fixture path (CertificateScenario, startup check bypassed) with a compliant certificate
// connects, so the refusals above come from the certificate alone.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-131-CLIENT-POLICY-FAMILIES, scope=function)
TEST_P(CertificateValidationClientPolicyControl, TheSamePathWithACompliantCertificateConnects)
{
  start(valid_server());
  auto result = connect();
  EXPECT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
}

// CreateSessionResponse.serverCertificate names ANOTHER leaf (same key, issued by the intermediate) than the
// OPN SenderCertificate: the client refuses with Bad_SecurityChecksFailed (OPC 10000-4 5.6.2.2).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-132-OPN-CREATESESSION-MISMATCH, scope=function)
TEST_P(CertificateValidationOpnCreateSessionMismatch, AnotherLeafInCreateSessionIsRefused)
{
  start(valid_server());
  rewrite_create_session_certificate(
    shared_pki()
      .leaf(GetParam().policy, CertificateCase::ChainIncomplete, Role::Server)
      .certificate->der_encoding());
  auto result = connect();
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadSecurityChecksFailed})
    << "got 0x" << std::hex << result.status_code().as_uint32();
}

// Control (decision 26): CreateSessionResponse.serverCertificate carries the SAME leaf followed by a chain
// the OPN did not carry; the leaf is what is compared, so the client connects.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-132-OPN-CREATESESSION-MISMATCH, scope=function)
TEST_P(CertificateValidationOpnCreateSessionMismatch, TheSameLeafWithAChainInCreateSessionConnects)
{
  start(valid_server());
  LeafMaterial withChain = valid_server();
  withChain.presentedIssuers = {shared_pki().root(family_of(GetParam().policy))};
  rewrite_create_session_certificate(chain_der(withChain));
  auto result = connect();
  EXPECT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
}

INSTANTIATE_TEST_SUITE_P(PolicyFamilies, CertificateValidationClientPolicyFamilies,
  ::testing::ValuesIn(policy_family_params()), matrix_param_name);

INSTANTIATE_TEST_SUITE_P(Controls, CertificateValidationClientPolicyControl,
  ::testing::ValuesIn(control_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(Controls, CertificateValidationOpnCreateSessionMismatch,
  ::testing::ValuesIn(control_params()), channel_param_name);

}  // namespace
