// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief I2: the client validates the SERVER certificate, real client against real server, over all 11
///        SecurityPolicies x {Sign, SignAndEncrypt} (certificate coverage review "Integration scope").
///
/// The faulty certificate is the server's own. The client API reports the exact Table 106 code (the client is
/// not bound by the server's Bad_SecurityChecksFailed wire rule). A successful connect means both the OPN and
/// the CreateSession check accepted the server's presented chain. Also: the per-connection trust prompt
/// (owner decision 22.5: an accepted self-signed certificate connects; an accepted leaf whose CA is unknown
/// is still Bad_CertificateChainIncomplete and names the issuer; the same leaf with its chain presented
/// connects), and revalidation resubmitting the stored request after a trust change (approved "Client
/// revalidation").
///
/// Ledger correction (completeness review 2026-10-02): the host-name check (Table 106 step 8). The server's
/// certificate names "localhost" only; dialling the same server as 127.0.0.1 is the one variable.
/// Unsuppressed, the client API reports Bad_CertificateHostNameInvalid; with SuppressHostNameInvalid in the
/// client's validation options the connection is established and the suppressed error is logged as a warning
/// (approved item 9, client side). Both rows reuse the cached server and the cached client of the
/// configuration.
///
/// SCOPE NOTE: the two policy-violation cases are not run here. A server whose own certificate violates an
/// endpoint policy refuses to start (approved decision F), so no SDK server can present one; the startup
/// refusal is asserted in certificate_validation_trust_list_live_tests.cpp and the client-side policy rule at
/// the validator (U7).
///
/// TIER: Client::try_connect_sync / Client::try_easy_connect_sync (tier 2).

#include "certificate_validation_integration_fixture.h"

#include "ua_client_observers.h"
#include "ua_easy_connect_policy.h"
#include "sanitizer_budget.h"

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::test_helpers::certificate_validation;

namespace
{

std::vector<CertificateCase> client_side_cases(bool accepted)
{
  std::vector<CertificateCase> cases;
  for (auto certificateCase : accepted ? accepted_cases() : refused_cases())
  {
    if (certificateCase != CertificateCase::PolicyKeyLength &&
        certificateCase != CertificateCase::PolicySignature)
      cases.push_back(certificateCase);
  }
  return cases;
}

/// Records every disconnect reason of a Connection.
class DisconnectRecorder : public client::ConnectionObserver
{
public:
  void on_disconnected(const client::Connection& /*connection*/, StatusCode reason,
    std::shared_ptr<const ErrorDetail> /*detail*/) override
  {
    std::lock_guard lock(mMutex);
    mReasons.push_back(reason);
  }

  std::vector<StatusCode> reasons() const
  {
    std::lock_guard lock(mMutex);
    return mReasons;
  }

private:
  mutable std::mutex mMutex;
  std::vector<StatusCode> mReasons;
};

/// The server's own certificate IS the case variable, so each case starts a server presenting it (on the
/// cached pool). The client is reused per channel configuration (MatrixCache::client_for) unless the test
/// changes the client's trust material (trust prompt, revalidation), which then gets its own client.
class CertificateValidationClientMatrix : public ::testing::TestWithParam<MatrixParam>
{
protected:
  void SetUp() override
  {}

  void TearDown() override
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
    mConnection.reset();
    mOwnClient.reset();
    mClient = nullptr;
    mServer.reset();
    mServerStore.reset();
    mClientStore.reset();
  }

  static MatrixPki& pki()
  {
    return shared_pki();
  }

  /// Starts a server presenting @p serverOwn. With @p clientTrust the client is a dedicated one holding that
  /// trust material; without it the cached client of the configuration (family trust, @p clientOptions).
  void start(const LeafMaterial& serverOwn, std::optional<TrustMaterial> clientTrust,
    TrustListValidationOptions clientOptions)
  {
    const auto& param = GetParam();
    auto& cache = MatrixCache::instance();
    mServerStore = make_store(cache.new_directory("i2_server"),
      cache.server_pool().executor(),
      pki().crypto(),
      validation_options_for(CertificateCase::Valid),
      pki().trust_material(family()),
      &serverOwn,
      application_certificate_type(param.policy));
    mServer = std::make_unique<MatrixServer>(cache.server_pool(),
      pki().crypto(),
      MatrixServer::Options{.policy = param.policy,
        .mode = param.mode,
        .applicationStore = mServerStore,
        .userTokenStore = nullptr,
        .x509Authenticator = nullptr,
        .auditing = true,
        .userTokenSecurityPolicy = std::nullopt,
        .localDiscoveryServer = false});
    ASSERT_TRUE(mServer->start().is_good()) << "fixture: the server must start";

    if (!clientTrust.has_value())
    {
      auto& entry = cache.client_for(param.policy, param.mode, clientOptions);
      mClientStore = entry.store;
      mWarnings = entry.warnings;
      mWarnings->clear();
      mClient = &*entry.client;
      return;
    }
    mClientStore = make_store(cache.new_directory("i2_client"),
      cache.client_pool().executor(),
      pki().crypto(),
      clientOptions,
      *clientTrust,
      &pki().leaf(param.policy, CertificateCase::Valid, Role::Client),
      application_certificate_type(param.policy));
    mWarnings = std::make_shared<WarningRecorder>();
    mOwnClient.emplace(make_matrix_client(cache.client_pool(), pki().crypto(), mClientStore, mWarnings));
    mClient = &*mOwnClient;
  }

  ConnectResult connect(std::optional<std::chrono::milliseconds> channelLifetime = std::nullopt)
  {
    auto config = matrix_connection_config(mServer->endpoint_url(), GetParam().policy, GetParam().mode);
    config.channelLifetime = channelLifetime;
    auto result = reported(mClient->try_connect_sync(std::move(config)));
    if (result.is_good())
      mConnection.emplace(std::move(result).value());
    return result;
  }

  /// Easy connect with a prompt answering AcceptForThisSession; records each prompt's reason.
  ConnectResult easy_connect_accepting(std::vector<StatusCode>& promptReasons)
  {
    client::EasyConnectConfig policy;
    policy.endpointUrl = mServer->endpoint_url();
    policy.trustPrompt = [&promptReasons](const X509Certificate& /*certificate*/, StatusCode reason)
    {
      promptReasons.push_back(reason);
      return client::TrustDecision::AcceptForThisSession;
    };
    policy.customize = [](client::ConnectionConfig& config)
    {
      config.reconnect = std::nullopt;
    };
    auto result = reported(mClient->try_easy_connect_sync(std::move(policy)));
    if (result.is_good())
      mConnection.emplace(std::move(result).value());
    return result;
  }

  Family family() const
  {
    return family_of(GetParam().policy);
  }

  std::shared_ptr<CertificateStore> mServerStore;
  std::shared_ptr<CertificateStore> mClientStore;
  std::shared_ptr<WarningRecorder> mWarnings;
  std::unique_ptr<MatrixServer> mServer;
  std::optional<client::Client> mOwnClient;
  client::Client* mClient{nullptr};
  std::optional<client::Connection> mConnection;
};

class CertificateValidationClientRefusal : public CertificateValidationClientMatrix
{};

class CertificateValidationClientAcceptance : public CertificateValidationClientMatrix
{};

class CertificateValidationClientTrustPrompt : public CertificateValidationClientMatrix
{};

class CertificateValidationClientRevalidation : public CertificateValidationClientMatrix
{};

/// Host-name rows: the cached server presenting the Valid certificate (SAN host "localhost" only), dialled by
/// IP address.
class CertificateValidationClientHostName : public CertificateValidationClientMatrix
{
protected:
  ConnectResult connect_by_ip(TrustListValidationOptions clientOptions)
  {
    const auto& param = GetParam();
    auto& cache = MatrixCache::instance();
    auto& server = cache.server_for(param.policy, param.mode, validation_options_for(CertificateCase::Valid));
    auto& entry = cache.client_for(param.policy, param.mode, clientOptions);
    mWarnings = entry.warnings;
    mWarnings->clear();
    mClient = &*entry.client;
    std::string url = server.server->endpoint_url();
    const auto host = url.find("localhost");
    if (host != std::string::npos)
      url.replace(host, std::string_view{"localhost"}.size(), "127.0.0.1");
    auto result =
      reported(mClient->try_connect_sync(matrix_connection_config(url, param.policy, param.mode)));
    if (result.is_good())
      mConnection.emplace(std::move(result).value());
    return result;
  }
};

// Refused cases: the client API reports the exact Table 106 code for the server's certificate.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-55-CLIENT-MATRIX, scope=function)
TEST_P(CertificateValidationClientRefusal, TheClientRefusesTheFaultyServerCertificateWithTheTable106Code)
{
  const auto certificateCase = GetParam().certificateCase;
  start(pki().leaf(GetParam().policy, certificateCase, Role::Server),
    std::nullopt,
    validation_options_for(certificateCase));
  auto result = connect();

  ASSERT_TRUE(result.is_bad()) << "a server certificate refused by Table 106 must not connect";
  EXPECT_EQ(result.status_code(), expected_outcome(certificateCase).table106)
    << "the client API must report the exact Table 106 code, got 0x" << std::hex
    << result.status_code().as_uint32();
}

// Accepted cases (the controls): the connection (OPN and CreateSession, with the presented chain) is
// established; a suppressed expiry is logged as a warning (approved item 9, client side).
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-55-CLIENT-MATRIX, scope=function)
TEST_P(CertificateValidationClientAcceptance, TheClientAcceptsTheConformingServerCertificate)
{
  const auto certificateCase = GetParam().certificateCase;
  start(pki().leaf(GetParam().policy, certificateCase, Role::Server),
    std::nullopt,
    validation_options_for(certificateCase));
  auto result = connect();

  ASSERT_TRUE(result.is_good()) << "a server certificate Table 106 accepts must connect: 0x" << std::hex
                                << result.status_code().as_uint32();
  if (expected_outcome(certificateCase).suppressedError.has_value())
  {
    EXPECT_TRUE(eventually([&] { return mWarnings->any_contains("CertificateTimeInvalid"); }))
      << "the client must log a warning naming the suppressed Bad_CertificateTimeInvalid";
  }
}

// Trust prompt, accepted self-signed: the prompt sees Bad_CertificateUntrusted and the connect succeeds.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-56-CLIENT-TRUST-PROMPT, scope=function)
TEST_P(CertificateValidationClientTrustPrompt, AnAcceptedSelfSignedServerCertificateConnects)
{
  start(pki().leaf(GetParam().policy, CertificateCase::Untrusted, Role::Server),
    std::nullopt,
    validation_options_for(CertificateCase::Valid));
  std::vector<StatusCode> promptReasons;
  auto result = easy_connect_accepting(promptReasons);

  ASSERT_EQ(promptReasons.size(), 1u) << "the prompt must be asked exactly once";
  EXPECT_EQ(promptReasons[0], StatusCode{Status::BadCertificateUntrusted});
  EXPECT_TRUE(result.is_good()) << "an accepted self-signed certificate must connect: 0x" << std::hex
                                << result.status_code().as_uint32();
}

// Trust prompt, accepted CA-issued leaf whose CA is unknown and not presented: the chain must still complete
// (22.5), so the connect fails Bad_CertificateChainIncomplete and the detail names the missing issuer.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-56-CLIENT-TRUST-PROMPT, scope=function)
TEST_P(CertificateValidationClientTrustPrompt, AnAcceptedLeafWithAnUnknownCaIsChainIncompleteNamingTheIssuer)
{
  start(pki().leaf(GetParam().policy, CertificateCase::ChainIncomplete, Role::Server),
    TrustMaterial{},
    validation_options_for(CertificateCase::Valid));
  std::vector<StatusCode> promptReasons;
  auto result = easy_connect_accepting(promptReasons);

  ASSERT_EQ(promptReasons.size(), 1u)
    << "a chain-incomplete certificate is a trust-class failure: prompt once";
  EXPECT_EQ(promptReasons[0], StatusCode{Status::BadCertificateChainIncomplete});
  ASSERT_TRUE(result.is_bad()) << "accepting the leaf for this connection must not complete its chain";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateChainIncomplete})
    << "the refusal must carry Bad_CertificateChainIncomplete";
  EXPECT_TRUE(detail_chain_has(result.shared_detail(), std::nullopt, "Intermediate"))
    << "the refusal must name the missing issuer (the family intermediate)";
}

// Control for the row above: the same leaf, the server presenting intermediate and root, connects once
// accepted for this connection.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-56-CLIENT-TRUST-PROMPT, scope=function)
TEST_P(CertificateValidationClientTrustPrompt, AnAcceptedLeafWithItsChainPresentedConnects)
{
  LeafMaterial presented = pki().leaf(GetParam().policy, CertificateCase::ChainIncomplete, Role::Server);
  presented.presentedIssuers = {pki().intermediate(family()), pki().root(family())};
  // Nothing trusted; the CRLs are held so the revocation check (on by default) can complete.
  start(presented, pki().revocation_material(family()), validation_options_for(CertificateCase::Valid));
  std::vector<StatusCode> promptReasons;
  auto result = easy_connect_accepting(promptReasons);

  ASSERT_EQ(promptReasons.size(), 1u);
  EXPECT_EQ(promptReasons[0], StatusCode{Status::BadCertificateUntrusted})
    << "a complete chain nothing in which is trusted is a Trust List failure";
  EXPECT_TRUE(result.is_good()) << "an accepted leaf with its complete chain presented must connect: 0x"
                                << std::hex << result.status_code().as_uint32();
}

// Revalidation resubmits the STORED request: with the server presenting its intermediate, renewals keep the
// connection (the presented chain is part of the request); once the client stops trusting the root, the next
// revalidation refuses with Bad_CertificateUntrusted (the root stays in the issuer list, so the chain still
// builds) and the connection is dropped.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-57-CLIENT-REVALIDATION, scope=function)
TEST_P(CertificateValidationClientRevalidation, RevalidationResubmitsTheStoredRequestAfterATrustChange)
{
  const auto lifetime = std::chrono::milliseconds{1500};
  start(pki().leaf(GetParam().policy, CertificateCase::ValidWithPresentedChain, Role::Server),
    pki().trust_material(family()),
    validation_options_for(CertificateCase::Valid));
  mClientStore->add_to_issuer_certificates_sync(pki().root(family()));
  auto result = connect(lifetime);
  ASSERT_TRUE(result.is_good()) << "0x" << std::hex << result.status_code().as_uint32();
  auto disconnects = std::make_shared<DisconnectRecorder>();
  mConnection->set_connection_observer(disconnects);

  // Control: two renewals with unchanged trust; the resubmitted request still carries the presented chain.
  std::this_thread::sleep_for(ua::test_utils::scaled(lifetime * 2));
  EXPECT_TRUE(disconnects->reasons().empty()) << "revalidation with unchanged trust must keep the connection";

  mClientStore->remove_from_trusted_certificates_sync(thumbprint_hex(*pki().root(family())));
  EXPECT_TRUE(eventually(
    [&]
    {
      const auto reasons = disconnects->reasons();
      return std::find(reasons.begin(), reasons.end(), StatusCode{Status::BadCertificateUntrusted}) !=
             reasons.end();
    },
    lifetime * 4))
    << "after the trust change the revalidation must refuse with Bad_CertificateUntrusted";
}

// Unsuppressed host-name mismatch: Bad_CertificateHostNameInvalid at the client API, not connected.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-122-CLIENT-HOST-NAME, scope=function)
TEST_P(CertificateValidationClientHostName, AnUnsuppressedHostNameMismatchIsRefused)
{
  auto result = connect_by_ip(validation_options_for(CertificateCase::Valid));
  ASSERT_TRUE(result.is_bad()) << "a server certificate not naming the dialled host must be refused";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadCertificateHostNameInvalid})
    << "got 0x" << std::hex << result.status_code().as_uint32();
}

// Suppressed host-name mismatch (the control: the same server and URL, only the suppression bit differs):
// connected, and the client logs a warning naming Bad_CertificateHostNameInvalid.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-122-CLIENT-HOST-NAME, scope=function)
TEST_P(CertificateValidationClientHostName, ASuppressedHostNameMismatchConnectsWithAWarning)
{
  using Bit = TrustListValidationOptions::Bit;
  auto result = connect_by_ip(
    TrustListValidationOptions{Bit::CheckRevocationStatusOffline, Bit::SuppressHostNameInvalid});
  ASSERT_TRUE(result.is_good()) << "a suppressed host-name mismatch must connect: 0x" << std::hex
                                << result.status_code().as_uint32();
  EXPECT_TRUE(eventually([&] { return mWarnings->any_contains("CertificateHostNameInvalid"); }))
    << "the client must log a warning naming the suppressed Bad_CertificateHostNameInvalid";
}

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationClientHostName,
  ::testing::ValuesIn(channel_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(Refused, CertificateValidationClientRefusal,
  ::testing::ValuesIn(matrix_params(client_side_cases(false))), matrix_param_name);

INSTANTIATE_TEST_SUITE_P(Accepted, CertificateValidationClientAcceptance,
  ::testing::ValuesIn(matrix_params(client_side_cases(true))), matrix_param_name);

/// The channels easy-connect can select: its ranking never selects Basic128Rsa15 (client design 7.3A,
/// default_easy_connect_ranker), so the trust prompt cannot be reached on it.
std::vector<MatrixParam> easy_connect_channel_params()
{
  auto params = channel_params();
  std::erase_if(params, [](const MatrixParam& p) { return p.policy == SecurityPolicyId::Basic128Rsa15; });
  return params;
}

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationClientTrustPrompt,
  ::testing::ValuesIn(easy_connect_channel_params()), channel_param_name);

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationClientRevalidation,
  ::testing::ValuesIn(channel_params()), channel_param_name);

}  // namespace
