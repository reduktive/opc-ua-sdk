// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief I1: the server validates the CLIENT certificate, real client against real server, over all 11
///        SecurityPolicies x {Sign, SignAndEncrypt} and the core certificate set
///        (certificate coverage review "Integration scope (owner 2026-10-02)").
///
/// The faulty certificate is the client's own. Each refused case asserts, from the oracle in
/// certificate_validation_integration_fixture.h (OPC 10000-4 Table 106 + owner decisions):
///   - the client sees Bad_SecurityChecksFailed (the wire code for every server-side failure, owner
///   decision);
///   - ServerObserver::on_certificate_rejected receives the exact Table 106 code AND the presented
///   certificate
///     (decision 27);
///   - the server emits the Table 106 audit event type whose mandatory Certificate property is the presented
///     certificate (OPC 10000-5 6.4.12);
///   - the server's Rejected list holds the certificate when the rule says so (untrusted, chain incomplete).
/// Each accepted case is the control: the same server, the same channel, a certificate differing only in the
/// one property under test. The suppressed-expiry case is accepted AND raises on_certificate_error_suppressed
/// with Bad_CertificateTimeInvalid plus the expiry audit event (approved item 9).
///
/// Ledger corrections (completeness review 2026-10-02): an intermediate the server TRUSTS with the root only
/// in its issuer list accepts the leaf (Table 106 step 5 is satisfied by any trusted chain certificate), and
/// a client certificate whose URI differs from the client's ApplicationUri is refused with the DataMismatch
/// audit event carrying InvalidUri (OPC 10000-5 6.4.13).
///
/// REUSE: one server per channel configuration (MatrixCache), PKI once per binary, keys from the test key
/// cache. TIER: the client is driven through Client::try_connect_sync (tier 2), the highest public tier.
/// Curves the OpenSSL build cannot generate are skipped at run time.

#include "certificate_validation_integration_fixture.h"

#include <gtest/gtest.h>

using namespace ua;
using namespace ua::test_helpers::certificate_validation;

namespace
{

/// One cached server per channel configuration (MatrixCache); each case brings a fresh client presenting the
/// case's certificate and resets the server's recorded hooks and events.
class CertificateValidationServerMatrix : public ::testing::TestWithParam<MatrixParam>
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
    mClientStore.reset();
  }

  /// The client presents @ref leaf(); the cached server trusts the family root and holds its CRLs.
  ConnectResult connect()
  {
    const auto& param = GetParam();
    mServer = &MatrixCache::instance().server_for(
      param.policy, param.mode, validation_options_for(param.certificateCase));
    mServer->server->reset_observations();
    return connect_to(*mServer->server, leaf());
  }

  /// A fresh client presenting @p own connects to @p target.
  ConnectResult connect_to(MatrixServer& target, const LeafMaterial& own)
  {
    const auto& param = GetParam();
    auto& cache = MatrixCache::instance();
    auto& pki = shared_pki();
    mClientStore = make_store(cache.new_directory("i1_client"),
      cache.client_pool().executor(),
      pki.crypto(),
      validation_options_for(CertificateCase::Valid),
      pki.trust_material(family_of(param.policy)),
      &own,
      application_certificate_type(param.policy));
    mClient.emplace(make_matrix_client(cache.client_pool(), pki.crypto(), mClientStore));
    auto result = reported(
      mClient->try_connect_sync(matrix_connection_config(target.endpoint_url(), param.policy, param.mode)));
    if (result.is_good())
      mConnection.emplace(std::move(result).value());
    return result;
  }

  const LeafMaterial& leaf() const
  {
    return shared_pki().leaf(GetParam().policy, GetParam().certificateCase, Role::Client);
  }

  const MatrixServer& server() const
  {
    return *mServer->server;
  }

  MatrixCache::ServerEntry* mServer{nullptr};
  std::shared_ptr<CertificateStore> mClientStore;
  std::optional<client::Client> mClient;
  std::optional<client::Connection> mConnection;
};

class CertificateValidationServerRefusal : public CertificateValidationServerMatrix
{};

class CertificateValidationServerAcceptance : public CertificateValidationServerMatrix
{};

class CertificateValidationServerIntermediateTrust : public CertificateValidationServerMatrix
{};

// Refused cases: the client sees Bad_SecurityChecksFailed where the Table 106 row says so and the row's own
// code where it does not, the server reports the exact Table 106 code to its observer, raises the Table 106
// audit event, and files untrusted / chain-incomplete certificates as Rejected.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-54-SERVER-MATRIX, scope=function)
TEST_P(CertificateValidationServerRefusal, TheServerRefusesTheFaultyClientCertificate)
{
  const auto expected = expected_outcome(GetParam().certificateCase);
  auto result = connect();

  ASSERT_TRUE(result.is_bad()) << "a client certificate refused by Table 106 must not connect";
  EXPECT_EQ(result.status_code(), expected.wire)
    << "Bad_SecurityChecksFailed only where the Table 106 row says to report it back, else the row's code";
  EXPECT_TRUE(
    eventually([&] { return server().hooks().rejected_with(expected.table106, *leaf().certificate); }))
    << "on_certificate_rejected must receive the Table 106 code 0x" << std::hex
    << expected.table106.as_uint32() << " and the PRESENTED certificate (decision 27)";
  ASSERT_TRUE(expected.auditEventType.has_value());
  EXPECT_TRUE(eventually(
    [&] { return server().events().saw_certificate_event(*expected.auditEventType, *leaf().certificate); }))
    << "the server must raise the Table 106 audit event type whose Certificate property is the presented "
       "certificate (OPC 10000-5 6.4.12)";
  if (expected.inRejectedStore)
  {
    EXPECT_TRUE(eventually([&] { return rejected_store_contains(*mServer->store, *leaf().certificate); }))
      << "an untrusted or chain-incomplete client certificate must be filed in the Rejected list";
  }
}

// Accepted cases (the controls): the connection is established, nothing is rejected; the suppressed expiry is
// reported through on_certificate_error_suppressed and audited.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-54-SERVER-MATRIX, scope=function)
TEST_P(CertificateValidationServerAcceptance, TheServerAcceptsTheConformingClientCertificate)
{
  const auto expected = expected_outcome(GetParam().certificateCase);
  auto result = connect();

  ASSERT_TRUE(result.is_good()) << "a client certificate Table 106 accepts must connect: 0x" << std::hex
                                << result.status_code().as_uint32();
  EXPECT_TRUE(server().hooks().rejected().empty()) << "an accepted certificate must not be reported rejected";
  if (expected.suppressedError.has_value())
  {
    EXPECT_TRUE(eventually(
      [&] { return server().hooks().suppressed_count(*expected.suppressedError, *leaf().certificate) > 0; }))
      << "the suppressed expiry must reach on_certificate_error_suppressed with the presented certificate";
    ASSERT_TRUE(expected.auditEventType.has_value());
    EXPECT_TRUE(eventually(
      [&] { return server().events().saw_certificate_event(*expected.auditEventType, *leaf().certificate); }))
      << "a suppressed error is always reported via auditing, naming the presented certificate";
  }
  else
  {
    EXPECT_TRUE(server().hooks().suppressed().empty()) << "nothing was suppressed for a valid certificate";
  }
}

// Ledger correction: a server that TRUSTS the intermediate and holds the root only in its issuer list accepts
// a leaf the intermediate issued, sent without its chain (the chain builds from the server's own lists, and
// the trusted intermediate satisfies the Trust List Check). The refusal arm is ChainIncomplete in
// CertificateValidationServerRefusal: the same leaf against a server holding neither.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-120-INTERMEDIATE-TRUSTED, scope=function)
TEST_P(CertificateValidationServerIntermediateTrust, ATrustedIntermediateWithTheRootAsIssuerAcceptsTheLeaf)
{
  const auto& param = GetParam();
  auto& cache = MatrixCache::instance();
  auto& pki = shared_pki();
  const auto family = family_of(param.policy);
  const auto familyTrust = pki.trust_material(family);
  auto store = make_store(cache.new_directory("i1_intermediate_server"),
    cache.server_pool().executor(),
    pki.crypto(),
    validation_options_for(CertificateCase::Valid),
    TrustMaterial{.trusted = {pki.intermediate(family)},
      .trustedCrls = familyTrust.issuerCrls,
      .issuerCrls = {pki.root_crl(family)}},
    &pki.leaf(param.policy, CertificateCase::Valid, Role::Server),
    application_certificate_type(param.policy));
  store->add_to_issuer_certificates_sync(pki.root(family));
  MatrixServer intermediateServer(cache.server_pool(),
    pki.crypto(),
    MatrixServer::Options{.policy = param.policy,
      .mode = param.mode,
      .applicationStore = store,
      .userTokenStore = nullptr,
      .x509Authenticator = nullptr,
      .auditing = true,
      .userTokenSecurityPolicy = std::nullopt,
      .localDiscoveryServer = false});
  ASSERT_TRUE(intermediateServer.start().is_good()) << "fixture: the server must start";

  auto result =
    connect_to(intermediateServer, pki.leaf(param.policy, CertificateCase::ChainIncomplete, Role::Client));
  EXPECT_TRUE(result.is_good())
    << "a trusted intermediate with the root in the issuer list must accept the leaf: 0x" << std::hex
    << result.status_code().as_uint32();
  EXPECT_TRUE(intermediateServer.hooks().rejected().empty());
  if (mConnection)
    (void)mConnection->try_close_sync();
  mConnection.reset();
}

INSTANTIATE_TEST_SUITE_P(AllChannels, CertificateValidationServerIntermediateTrust,
  ::testing::ValuesIn(channel_params()), channel_param_name);

/// The refused cases an SDK client can present. A client refuses its own certificate when it violates every
/// SecurityPolicy (at create) or the endpoint's (at channel open), so the policy cases never reach the server
/// from an SDK client; the server's refusal of them is proven on its OPN decode path by the unit tests
/// (UascSecurityPolicyTests, the U7 policy matrix).
std::vector<CertificateCase> server_refused_cases()
{
  auto cases = refused_cases();
  std::erase_if(cases,
    [](CertificateCase c)
    { return c == CertificateCase::PolicyKeyLength || c == CertificateCase::PolicySignature; });
  return cases;
}

INSTANTIATE_TEST_SUITE_P(Refused, CertificateValidationServerRefusal,
  ::testing::ValuesIn(matrix_params(server_refused_cases())), matrix_param_name);

INSTANTIATE_TEST_SUITE_P(Accepted, CertificateValidationServerAcceptance,
  ::testing::ValuesIn(matrix_params(accepted_cases())), matrix_param_name);

}  // namespace
