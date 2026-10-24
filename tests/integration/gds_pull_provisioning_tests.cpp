// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief End-to-end pull provisioning (OPC 10000-12 7.6, Figures 12, 16 and 17): an SDK client application
///        drives the public PullCertificateManager against the GDS emulator (tests/integration/helpers/
///        gds_emulator.h), which serves the standard GDS model with a real test CA. Each scenario ends with
///        an observation the application's own behaviour produces - a channel it can or cannot open - not
///        only what the GDS recorded.

#include "gds_emulator.h"

#include "test_log_sink.h"
#include "test_utilities.h"

#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_crypto.h"
#include "ua_error_chain.h"
#include "ua_error_detail.h"
#include "ua_guid.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_pull_certificate_manager.h"
#include "ua_role_configuration.h"
#include "ua_server.h"
#include "ua_server_authentication.h"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace
{

using namespace ua;
using namespace std::chrono_literals;
using ua::test::GdsApplicationRecord;
using ua::test::GdsApproval;
using ua::test::GdsEmulator;
using ua::test::GdsMethod;

constexpr std::string_view applicationUri{"urn:test:pull:application"};
constexpr std::string_view plantUri{"urn:test:pull:plant"};

/// Every store and the emulator share this credential: CertificateStoreFiles writes private keys encrypted
/// with it, and a server reopens a seeded directory under the credential that seeded it.
std::shared_ptr<const Crypto> make_crypto()
{
  return create_default_crypto([] { return ua::SecureString{"password"}; });
}

/// A server the application connects to after provisioning (the "plant"): it trusts only the GDS's CA (with
/// its CRL), so a channel opens only for a certificate the GDS issued. Shut down explicitly; the destructor
/// does not block.
class PlantServer
{
public:
  /// @p caIssued: the plant holds a certificate the GDS's CA issued (so the GDS can revoke it) rather than a
  /// self-signed one.
  void start(const std::shared_ptr<const Crypto>& crypto, const std::filesystem::path& storePath,
    GdsEmulator& gds, bool caIssued = false)
  {
    std::filesystem::create_directories(storePath);
    Crypto::Name subject;
    subject.commonName = "Pull provisioning plant";
    subject.organization = "Test";
    Crypto::SubjectAlternateName alternateName;
    alternateName.uris.push_back(std::string{plantUri});
    alternateName.hostnames.push_back("localhost");
    alternateName.ipAddresses.push_back(boost::asio::ip::make_address("127.0.0.1"));  // the endpoint host
    auto identity = crypto->try_create_self_signed_application_instance_certificate_sync(
      subject, DateTime{2050, 1, 1, 0, 0, 0}, alternateName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(identity.is_good());
    auto [keys, certificate] = std::move(identity).value();
    if (caIssued)
    {
      certificate = gds.issue_certificate(keys, subject, alternateName);
    }
    mCertificate = certificate;

    auto store = CertificateStoreFiles::create(mPool.executor(),
      crypto,
      {.trustListPath = storePath,
        .validationOptions =
          ApplicationConfig::FileTrustListConfig{}.defaultApplicationGroupTrustListValidationOptions});
    CertificateStore::ApplicationCertificate own;
    own.certificateType = CertificateType::RsaSha256Application;
    own.certificate = certificate;
    own.keys = std::move(keys);
    store->add_to_application_certificates_sync(own);
    store->add_to_trusted_certificates_sync(gds.ca_certificate());
    store->add_to_trusted_crls_sync(gds.ca_crl());

    auto application = ua::test_utils::create_test_config();
    application.application_description_part().applicationUri = std::string{plantUri};
    application.file_trust_list_configuration().defaultApplicationGroupTrustListPath = storePath;
    server::ServerComponents components{
      .crypto = crypto, .logSink = ua::test_helpers::test_log_sink(), .logLevel = LogLevel::Debug};
    components.authenticator = std::make_shared<server::AnonymousAuthenticator>();
    // An anonymous session needs a Role to be activated; the scenarios only open sessions.
    components.roleConfiguration = server::RoleConfiguration::from_well_known_grants(
      {{server::WellKnownRole::Observer, IdentityCriteriaType::Anonymous}});
    server::CreateConfig createConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(application)};
    mServer.emplace(server::Server::create(mPool.executor(), std::move(createConfig), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    const auto listener = mServer->listen_sync(std::move(bind), {});
    server::ServerEndpointConfig endpoint;
    endpoint.name = "Basic256Sha256_SignAndEncrypt";
    endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    endpoint.userIdentityTokens.push_back(
      server::create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(listener, std::move(endpoint));
    mServer->start_sync();
    const auto urls = mServer->advertised_urls(listener);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();
  }

  void shutdown()
  {
    if (mServer)
    {
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
      mServer.reset();
    }
    ua::test_utils::stop_pool_in_teardown(mPool, "pull-plant");
  }

  [[nodiscard]] const std::string& endpoint_url() const
  {
    return mEndpointUrl;
  }

  [[nodiscard]] std::shared_ptr<const X509Certificate> certificate() const
  {
    return mCertificate;
  }

private:
  boost::asio::thread_pool mPool{2};
  std::optional<server::Server> mServer;
  std::string mEndpointUrl;
  std::shared_ptr<const X509Certificate> mCertificate;
};

class GdsPullProvisioning : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = make_crypto();
    mTempDir =
      std::filesystem::temp_directory_path() / ("ua_gds_pull_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);
    auto created = GdsEmulator::create(
      {.executor = mServerPool.executor(), .crypto = mCrypto, .workDirectory = mTempDir / "gds"});
    ASSERT_TRUE(created.is_good()) << "emulator: " << ua::format(created.status_code());
    mGds = std::move(created).value();

    // The application: a self-signed certificate it was installed with, which the GDS accepts for the
    // registration channel (Figure 12 "Start Installation").
    Crypto::Name subject;
    subject.commonName = "Pull provisioning application";
    subject.organization = "Test";
    Crypto::SubjectAlternateName alternateName;
    alternateName.uris.push_back(std::string{applicationUri});
    alternateName.hostnames.push_back("localhost");
    auto identity = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      subject, DateTime{2050, 1, 1, 0, 0, 0}, alternateName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(identity.is_good());
    auto [keys, certificate] = std::move(identity).value();
    mInstallKeys = keys;
    mInstallCertificate = certificate;
    const auto storePath = mTempDir / "application";
    std::filesystem::create_directories(storePath);
    // The SDK's default validation options (revocation checked against the TrustList's CRLs), as an
    // application configured from file gets them.
    mStore = CertificateStoreFiles::create(mClientPool.executor(),
      mCrypto,
      {.trustListPath = storePath,
        .validationOptions =
          ApplicationConfig::FileTrustListConfig{}.defaultApplicationGroupTrustListValidationOptions});
    CertificateStore::ApplicationCertificate own;
    own.certificateType = CertificateType::RsaSha256Application;
    own.certificate = certificate;
    own.keys = std::move(keys);
    mStore->add_to_application_certificates_sync(own);
    mStore->add_to_trusted_certificates_sync(mGds->server_certificate());
    mGds->trust_client_certificate(certificate);

    auto configuration = ua::test_utils::create_test_config();
    configuration.application_description_part().applicationUri = std::string{applicationUri};
    mClient.emplace(client::Client::create(mClientPool.executor(),
      client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = std::move(configuration)},
      client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mStore,
        .logSink = ua::test_helpers::test_log_sink(),
        .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    if (mManager)
    {
      std::promise<VoidResult> stopped;
      mManager->stop_async([&stopped](VoidResult result) { stopped.set_value(std::move(result)); });
      (void)stopped.get_future().wait_for(10s);
      mManager.reset();
    }
    for (auto& connection : mConnections)
      (void)connection->try_close_sync();
    mConnections.clear();
    mPlant.shutdown();
    if (mGds)
      mGds->shutdown();
    mClient.reset();
    mGds.reset();
    ua::test_utils::stop_pool_in_teardown(mClientPool, "pull-client");
    ua::test_utils::stop_pool_in_teardown(mServerPool, "pull-gds");
    std::error_code error;
    std::filesystem::remove_all(mTempDir, error);
  }

  /// Figure 12: the application registers itself over SignAndEncrypt (FindApplications finds none, then
  /// RegisterApplication) and keeps the ApplicationId the GDS assigns.
  NodeId register_application()
  {
    auto connection = connect(mGds->endpoint_url(), mGds->server_certificate());
    if (!connection)
      return {};
    auto found = connection->typed().try_call_method_sync(mGds->directory_id(),
      mGds->method_id(GdsMethod::FindApplications),
      std::vector<Variant>{Variant{String{std::string{applicationUri}}}});
    EXPECT_TRUE(found.is_good() && found.value().is_good());
    GdsApplicationRecord record;
    record.applicationUri = std::string{applicationUri};
    record.applicationType = ApplicationType::Client;
    record.applicationNames.push_back(LocalizedText{"en", "Pull provisioning application"});
    record.productUri = "urn:test:pull:product";
    auto registered = connection->typed().try_call_method_sync(mGds->directory_id(),
      mGds->method_id(GdsMethod::RegisterApplication),
      std::vector<Variant>{mGds->encode_application_record(record)});
    EXPECT_TRUE(registered.is_good() && registered.value().is_good()) << "RegisterApplication";
    if (registered.is_bad() || registered.value().is_bad() ||
        registered.value().value().output_arguments().size() != 1)
      return {};
    const auto* applicationId = registered.value().value().output_arguments()[0].try_as<NodeId>();
    (void)connection->try_close_sync();
    return applicationId ? *applicationId : NodeId{};
  }

  /// A DER PKCS #10 request for @p keys naming the application (Figure 17 left: the key stays with the
  /// application).
  ByteString make_csr(const std::shared_ptr<const AsymmetricKeyPair>& keys)
  {
    Crypto::CreateCsrConfig parameters;
    parameters.subject.commonName = "Pull provisioning application";
    parameters.subject.organization = "Test";
    parameters.subjectKeys = keys;
    parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    parameters.keyUsage.digitalSignature = true;
    parameters.keyUsage.nonRepudiation = true;
    parameters.keyUsage.keyEncipherment = true;
    parameters.keyUsage.dataEncipherment = true;
    parameters.subjectAlternateName.uris.push_back(std::string{applicationUri});
    parameters.subjectAlternateName.hostnames.push_back("localhost");
    std::promise<ByteStringResult> promise;
    mCrypto->create_certificate_signing_request_async(
      parameters, [&promise](ByteStringResult result) { promise.set_value(std::move(result)); });
    auto csr = promise.get_future().get();
    EXPECT_TRUE(csr.is_good());
    return csr.is_good() ? csr.value() : ByteString{};
  }

  /// The public manager's configuration for this application: a default CertificateGroupConfig (the GDS
  /// chooses its DefaultApplicationGroup) and a fast poll so a scenario completes in one call.
  client::PullCertManagementConfig pull_config(const NodeId& applicationId)
  {
    client::PullCertManagementConfig config;
    config.gdsEndpointUrl = mGds->endpoint_url();
    config.bootstrapTrustStore = mStore;
    config.runtimeCertStore = mStore;
    config.gdsSecurityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.gdsServerCertificate = mGds->server_certificate();
    config.applicationId = applicationId;
    config.pollInitialDelay = 1ms;
    config.pollMaxRepeat = 2;
    config.pollBackoffMultiplier = 1.0;
    config.pollJitterPct = 0.0;
    config.updateFrequency = std::chrono::hours{24};
    return config;
  }

  void start(client::PullCertManagementConfig config)
  {
    mManager = mClient->start_pull_cert_management_sync(std::move(config));
    ASSERT_NE(mManager, nullptr);
  }

  /// One full Figure 16 cycle; the manager reports Good for a completed cycle, failed or not.
  void run_cycle()
  {
    auto promise = std::make_shared<std::promise<VoidResult>>();
    auto future = promise->get_future();
    mManager->force_cycle_async([promise](VoidResult result) { promise->set_value(std::move(result)); });
    ASSERT_EQ(future.wait_for(60s), std::future_status::ready) << "the pull cycle did not complete";
    ASSERT_TRUE(future.get().is_good());
  }

  std::shared_ptr<client::Connection> connect(
    const std::string& endpointUrl, std::shared_ptr<const X509Certificate> serverCertificate)
  {
    auto connected = try_connect(endpointUrl, std::move(serverCertificate));
    EXPECT_TRUE(connected.is_good()) << "connect: " << ua::format(connected.status_code());
    if (connected.is_bad())
      return nullptr;
    auto connection = std::make_shared<client::Connection>(std::move(connected).value());
    mConnections.push_back(connection);
    return connection;
  }

  Result<client::Connection> try_connect(
    const std::string& endpointUrl, std::shared_ptr<const X509Certificate> serverCertificate)
  {
    client::ConnectionConfig config;
    config.endpointUrl = endpointUrl;
    config.securityMode = MessageSecurityMode::SignAndEncrypt;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = std::move(serverCertificate);
    config.reconnect = std::nullopt;
    return mClient->try_connect_sync(std::move(config));
  }

  /// The application certificate the store now holds for @p type.
  std::shared_ptr<const X509Certificate> held_certificate(CertificateType type)
  {
    auto held = mStore->try_get_application_certificates_sync();
    EXPECT_TRUE(held.is_good());
    if (held.is_bad())
      return nullptr;
    for (const auto& certificate : held.value())
    {
      if (certificate.certificateType == type)
        return certificate.certificate;
    }
    return nullptr;
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::filesystem::path mTempDir;
  boost::asio::thread_pool mServerPool{4};
  boost::asio::thread_pool mClientPool{4};
  std::shared_ptr<GdsEmulator> mGds;
  std::shared_ptr<CertificateStore> mStore;
  std::shared_ptr<const AsymmetricKeyPair> mInstallKeys;
  std::shared_ptr<const X509Certificate> mInstallCertificate;
  std::optional<client::Client> mClient;
  std::shared_ptr<client::PullCertificateManager> mManager;
  std::vector<std::shared_ptr<client::Connection>> mConnections;
  PlantServer mPlant;
};

}  // namespace

// PULL-1 (Figures 12, 16, 17 left): first provisioning with the application's own key. The application
// registers, the cycle asks GetCertificateStatus (the GDS has issued nothing, so an update is required),
// makes a StartSigningRequest with a CSR over its key, finishes it, downloads the group's TrustList and
// commits the certificate and TrustList together. The proof is end to end: a plant server that trusts only
// the GDS's CA refuses the application before the cycle and accepts it after, and the application now trusts
// the plant because the GDS's TrustList carries it.
// @relation(AC-CL-PULLCRT-005-A-PULL-CYCLE-PROVISIONS-A-CERTIFICATE-AND-TRUSTLIST-A-PEER-ACCEPTS, scope=function)
TEST_F(GdsPullProvisioning, FirstProvisioningWithTheApplicationsOwnKeyIsAcceptedByAPlantTrustingTheGds)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  mPlant.start(mCrypto, mTempDir / "plant", *mGds);
  mGds->add_trusted_certificate(mGds->default_application_group_id(), mPlant.certificate());

  auto before = try_connect(mPlant.endpoint_url(), mPlant.certificate());
  EXPECT_TRUE(before.is_bad()) << "control: before provisioning neither side trusts the other";
  if (before.is_good())
    (void)std::move(before).value().try_close_sync();

  auto config = pull_config(applicationId);
  client::CertificateGroupConfig group;  // the defaults: GDS-chosen group, RSA, signing request
  group.certificateRequest = make_csr(mInstallKeys);
  config.certificateGroups.push_back(std::move(group));
  start(std::move(config));
  run_cycle();

  const auto info = mManager->pull_cert_info();
  EXPECT_EQ(info->state, client::PullCertManagementState::Idle);
  EXPECT_EQ(info->lastError, nullptr) << (info->lastError ? ua::to_string(*info->lastError) : std::string{});
  ASSERT_TRUE(info->lastCertCommitAt.has_value()) << "the certificate was committed";
  ASSERT_TRUE(info->lastTrustListCommitAt.has_value()) << "the TrustList was committed";
  EXPECT_EQ(mGds->call_count(GdsMethod::GetCertificateStatus), 1u);
  EXPECT_EQ(mGds->call_count(GdsMethod::StartSigningRequest), 1u);
  const auto issued = mGds->issued_certificates(applicationId);
  ASSERT_EQ(issued.size(), 1u);
  const auto held = held_certificate(CertificateType::RsaSha256Application);
  ASSERT_NE(held, nullptr);
  EXPECT_EQ(held->thumbprint(), issued.front().certificate->thumbprint()) << "the issued certificate is held";
  EXPECT_EQ(held->public_key(), mInstallKeys->public_key_der()) << "with the application's own key";

  auto after = connect(mPlant.endpoint_url(), mPlant.certificate());
  EXPECT_NE(after, nullptr) << "the plant accepts the GDS-issued certificate and the application trusts the "
                               "plant through the GDS TrustList";
}

// PULL-2 (Figure 17 right): the GDS creates the key pair. StartNewKeyPairRequest names no password, so the
// key FinishRequest delivers is unprotected (7.9.4/7.9.5, owner decision 2026-10-03); the application stores
// it under its own credential (a fresh store over the same directory reads it back with the application's
// Crypto), and the plant accepts the new certificate, which only its private key can prove.
// @relation(AC-CL-PULLCRT-005-A-GDS-GENERATED-KEY-IS-REQUESTED-UNPROTECTED-AND-HELD-UNDER-THE-APPLICATION-CREDENTIAL, scope=function)
TEST_F(GdsPullProvisioning, AGdsGeneratedKeyPairIsRequestedUnprotectedAndHeldUnderTheApplicationCredential)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  mPlant.start(mCrypto, mTempDir / "plant", *mGds);
  mGds->add_trusted_certificate(mGds->default_application_group_id(), mPlant.certificate());

  auto config = pull_config(applicationId);
  client::CertificateGroupConfig group;
  group.useNewKeyPair = true;
  group.privateKeyFormat = "PEM";
  config.certificateGroups.push_back(std::move(group));
  start(std::move(config));
  run_cycle();

  const auto info = mManager->pull_cert_info();
  EXPECT_EQ(info->lastError, nullptr) << (info->lastError ? ua::to_string(*info->lastError) : std::string{});
  ASSERT_TRUE(info->lastCertCommitAt.has_value());
  EXPECT_EQ(mGds->call_count(GdsMethod::StartNewKeyPairRequest), 1u);
  const auto held = held_certificate(CertificateType::RsaSha256Application);
  ASSERT_NE(held, nullptr);
  EXPECT_NE(held->public_key(), mInstallKeys->public_key_der())
    << "a new key pair replaced the installed one";
  const auto requested = mGds->last_arguments(GdsMethod::StartNewKeyPairRequest);
  ASSERT_EQ(requested.size(), 7u);
  const auto* password = requested[6].try_as<String>();
  EXPECT_TRUE(password == nullptr || password->empty()) << "the key is requested without a password";

  auto reopened = CertificateStoreFiles::create(mClientPool.executor(),
    mCrypto,
    {.trustListPath = mTempDir / "application",
      .validationOptions =
        ApplicationConfig::FileTrustListConfig{}.defaultApplicationGroupTrustListValidationOptions});
  auto persisted = reopened->try_get_application_certificates_sync();
  ASSERT_TRUE(persisted.is_good()) << ua::format(persisted.status_code());
  bool keyRead = false;
  for (const auto& entry : persisted.value())
    keyRead = keyRead || (entry.certificate && entry.certificate->thumbprint() == held->thumbprint() &&
                           entry.keys && entry.keys->public_key_der() == held->public_key());
  EXPECT_TRUE(keyRead) << "the stored key reopens under the application's own credential";

  auto after = connect(mPlant.endpoint_url(), mPlant.certificate());
  EXPECT_NE(after, nullptr) << "the GDS-generated key works on a channel";
}

// PULL-3 (Table 21 FinishRequest, Figure 16 SigningRequestPending): approval is pending past the repeat
// count. The RequestId is kept, the next cycle finishes it with FinishRequest alone - no second
// StartSigningRequest - and the certificate is committed then.
// @relation(AC-CL-PULLCRT-003-A-PENDING-REQUEST-IS-FINISHED-IN-A-LATER-CYCLE-WITHOUT-A-NEW-REQUEST, scope=function)
TEST_F(GdsPullProvisioning, ARequestPendingApprovalIsFinishedInALaterCycleWithoutANewRequest)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  mGds->set_next_approval(GdsApproval::pending_for(3));  // the first cycle's 2 polls do not reach it

  auto config = pull_config(applicationId);
  client::CertificateGroupConfig group;
  group.certificateRequest = make_csr(mInstallKeys);
  config.certificateGroups.push_back(std::move(group));
  start(std::move(config));

  run_cycle();
  EXPECT_EQ(mGds->call_count(GdsMethod::StartSigningRequest), 1u);
  EXPECT_EQ(mGds->call_count(GdsMethod::FinishRequest), 2u)
    << "the poll burst is bounded by the repeat count";
  ASSERT_EQ(mManager->pull_cert_info()->pendingRequests.size(), 1u) << "the RequestId is kept";
  EXPECT_FALSE(mManager->pull_cert_info()->lastCertCommitAt.has_value());

  run_cycle();
  EXPECT_EQ(mGds->call_count(GdsMethod::StartSigningRequest), 1u) << "no second request is made";
  EXPECT_GE(mGds->call_count(GdsMethod::FinishRequest), 4u);
  EXPECT_TRUE(mManager->pull_cert_info()->pendingRequests.empty());
  ASSERT_TRUE(mManager->pull_cert_info()->lastCertCommitAt.has_value())
    << "the approved certificate is committed";
  ASSERT_EQ(mGds->issued_certificates(applicationId).size(), 1u);
  EXPECT_EQ(held_certificate(CertificateType::RsaSha256Application)->thumbprint(),
    mGds->issued_certificates(applicationId).front().certificate->thumbprint());
}

// PULL-4 (Table 21 FinishRequest): a rejected request. The cycle fails with the GDS's status, the installed
// certificate is kept, and the next cycle sends a new request (which this time is approved).
// @relation(AC-CL-PULLCRT-003-A-REJECTED-REQUEST-KEEPS-THE-CERTIFICATE-AND-IS-REQUESTED-AGAIN, scope=function)
TEST_F(GdsPullProvisioning, ARejectedRequestKeepsTheCertificateAndANewRequestFollows)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  mGds->set_next_approval(GdsApproval::reject(StatusCode{Status::BadRequestNotAllowed}));

  auto config = pull_config(applicationId);
  client::CertificateGroupConfig group;
  group.certificateRequest = make_csr(mInstallKeys);
  config.certificateGroups.push_back(std::move(group));
  start(std::move(config));

  run_cycle();
  auto info = mManager->pull_cert_info();
  EXPECT_EQ(info->state, client::PullCertManagementState::Failed);
  ASSERT_NE(info->lastError, nullptr);
  EXPECT_NE(ua::to_string(*info->lastError).find("BadRequestNotAllowed"), std::string::npos)
    << ua::to_string(*info->lastError);
  EXPECT_TRUE(info->pendingRequests.empty()) << "a rejected request is not resumed";
  EXPECT_EQ(
    held_certificate(CertificateType::RsaSha256Application)->thumbprint(), mInstallCertificate->thumbprint())
    << "the installed certificate is kept";

  run_cycle();  // the GDS approves the new request immediately
  EXPECT_EQ(mGds->call_count(GdsMethod::StartSigningRequest), 2u) << "a new request in the next cycle";
  ASSERT_EQ(mGds->issued_certificates(applicationId).size(), 1u);
  EXPECT_EQ(held_certificate(CertificateType::RsaSha256Application)->thumbprint(),
    mGds->issued_certificates(applicationId).back().certificate->thumbprint());
}

// PULL-5 and PULL-6 (Table 21 GetCertificateStatus / Update Required): once provisioned, a cycle in which the
// GDS reports no update makes no request and keeps the certificate; when the GDS flags the application, the
// next cycle obtains and commits a new certificate.
// @relation(AC-CL-PULLCRT-007-A-CERTIFICATE-IS-REQUESTED-ONLY-WHEN-THE-GDS-SAYS-AN-UPDATE-IS-REQUIRED, scope=function)
TEST_F(GdsPullProvisioning, ACertificateIsRequestedOnlyWhenTheGdsSaysAnUpdateIsRequired)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  auto config = pull_config(applicationId);
  client::CertificateGroupConfig group;
  group.certificateRequest = make_csr(mInstallKeys);
  config.certificateGroups.push_back(std::move(group));
  start(std::move(config));

  run_cycle();  // first provisioning
  ASSERT_EQ(mGds->issued_certificates(applicationId).size(), 1u);
  const auto first = held_certificate(CertificateType::RsaSha256Application);

  run_cycle();  // the GDS reports no update required
  EXPECT_EQ(mGds->call_count(GdsMethod::GetCertificateStatus), 2u);
  EXPECT_EQ(mGds->call_count(GdsMethod::StartSigningRequest), 1u)
    << "no request while the certificate is current";
  EXPECT_EQ(held_certificate(CertificateType::RsaSha256Application)->thumbprint(), first->thumbprint());

  mGds->set_update_required(applicationId, NodeId{}, NodeId{}, true);
  run_cycle();
  EXPECT_EQ(mGds->call_count(GdsMethod::StartSigningRequest), 2u) << "the flagged application renews";
  ASSERT_EQ(mGds->issued_certificates(applicationId).size(), 2u);
  EXPECT_EQ(held_certificate(CertificateType::RsaSha256Application)->thumbprint(),
    mGds->issued_certificates(applicationId).back().certificate->thumbprint())
    << "the renewed certificate is committed";
  EXPECT_NE(held_certificate(CertificateType::RsaSha256Application)->thumbprint(), first->thumbprint());
}

// PULL-7 (Table 21 GetTrustList / Read, CL-PULLCRT-006): the TrustList is the GDS's to change. A peer the
// application refuses is accepted after the GDS adds it and a cycle runs; once the GDS revokes the plant's
// GDS-issued certificate the application refuses it again after the next cycle. A cycle with an unchanged
// LastUpdateTime downloads nothing.
// @relation(AC-CL-PULLCRT-006-A-TRUSTLIST-CHANGE-PUBLISHED-BY-THE-GDS-TAKES-EFFECT-AFTER-THE-NEXT-CYCLE, scope=function)
TEST_F(GdsPullProvisioning, ATrustListChangePublishedByTheGdsTakesEffectAfterTheNextCycle)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  mPlant.start(mCrypto, mTempDir / "plant", *mGds);
  auto config = pull_config(applicationId);
  client::CertificateGroupConfig group;
  group.certificateRequest = make_csr(mInstallKeys);
  config.certificateGroups.push_back(std::move(group));
  start(std::move(config));

  run_cycle();  // provisioned, but the GDS TrustList does not carry the plant yet
  auto refused = try_connect(mPlant.endpoint_url(), mPlant.certificate());
  EXPECT_TRUE(refused.is_bad()) << "the application does not trust a plant the GDS has not published";
  if (refused.is_good())
    (void)std::move(refused).value().try_close_sync();

  const auto downloadsBefore = mGds->call_count(GdsMethod::GetTrustList);
  run_cycle();  // nothing changed on the GDS
  EXPECT_EQ(mGds->call_count(GdsMethod::GetTrustList), downloadsBefore + 1) << "LastUpdateTime is checked";

  mGds->add_trusted_certificate(mGds->default_application_group_id(), mPlant.certificate());
  run_cycle();
  auto accepted = try_connect(mPlant.endpoint_url(), mPlant.certificate());
  EXPECT_TRUE(accepted.is_good()) << "the GDS published the plant: " << ua::format(accepted.status_code());
  if (accepted.is_good())
    (void)std::move(accepted).value().try_close_sync();

  mGds->remove_trusted_certificate(mGds->default_application_group_id(), *mPlant.certificate());
  run_cycle();
  auto removed = try_connect(mPlant.endpoint_url(), mPlant.certificate());
  EXPECT_TRUE(removed.is_bad()) << "the GDS withdrew the plant; the application must refuse it again";
  if (removed.is_good())
    (void)std::move(removed).value().try_close_sync();
}

// PULL-7, revocation (Table 21 GetTrustList / Read; OPC 10000-4 6.1.3 revocation check): the application
// trusts the GDS's CA through the TrustList the GDS publishes, so it accepts a plant whose certificate that
// CA issued. When the GDS revokes the plant's certificate, the CRL it republishes reaches the application in
// the next cycle, and the application refuses the plant as revoked. Falsifiable: an application that does not
// commit the GDS's CRLs keeps accepting the revoked plant.
// @relation(AC-CL-PULLCRT-006-A-REVOCATION-PUBLISHED-BY-THE-GDS-TAKES-EFFECT-AFTER-THE-NEXT-CYCLE, scope=function)
TEST_F(GdsPullProvisioning, ARevocationPublishedByTheGdsTakesEffectAfterTheNextCycle)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  mPlant.start(mCrypto, mTempDir / "plant", *mGds, /*caIssued=*/true);
  mGds->add_trusted_certificate(mGds->default_application_group_id(), mGds->ca_certificate());
  mGds->add_trusted_crl(mGds->default_application_group_id(), mGds->ca_crl());
  auto config = pull_config(applicationId);
  client::CertificateGroupConfig group;
  group.certificateRequest = make_csr(mInstallKeys);
  config.certificateGroups.push_back(std::move(group));
  start(std::move(config));

  run_cycle();
  auto accepted = try_connect(mPlant.endpoint_url(), mPlant.certificate());
  ASSERT_TRUE(accepted.is_good()) << "control: the application trusts the plant through the GDS CA: "
                                  << ua::format(accepted.status_code());
  (void)std::move(accepted).value().try_close_sync();

  mGds->revoke_certificate(*mPlant.certificate());
  run_cycle();
  EXPECT_EQ(mManager->pull_cert_info()->lastError, nullptr);
  auto refused = try_connect(mPlant.endpoint_url(), mPlant.certificate());
  EXPECT_EQ(refused.status_code().as_status(), Status::BadCertificateRevoked)
    << "the CRL the GDS republished reached the application: " << ua::format(refused.status_code());
  if (refused.is_good())
    (void)std::move(refused).value().try_close_sync();
}

// PULL-8 (Figure 16 "Repeated for every certificate type"): RSA and ECC application certificates of the one
// DefaultApplicationGroup are both obtained in one cycle, the group's TrustList fetched once.
// @relation(AC-CL-PULLCRT-008-EVERY-CONFIGURED-CERTIFICATEGROUP-IS-PROCESSED-EACH-CYCLE, scope=function)
TEST_F(GdsPullProvisioning, RsaAndEccCertificatesOfOneGroupAreObtainedInOneCycle)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  auto config = pull_config(applicationId);
  client::CertificateGroupConfig rsa;
  rsa.certificateTypeId = NodeId{ObjectTypeId::RsaSha256ApplicationCertificateType};
  rsa.useNewKeyPair = true;
  client::CertificateGroupConfig ecc;
  ecc.certificateTypeId = NodeId{ObjectTypeId::EccNistP256ApplicationCertificateType};
  ecc.useNewKeyPair = true;
  config.certificateGroups = {rsa, ecc};
  start(std::move(config));
  run_cycle();

  const auto info = mManager->pull_cert_info();
  EXPECT_EQ(info->lastError, nullptr) << (info->lastError ? ua::to_string(*info->lastError) : std::string{});
  EXPECT_EQ(mGds->call_count(GdsMethod::GetCertificateStatus), 2u) << "one status per type";
  EXPECT_EQ(mGds->call_count(GdsMethod::StartNewKeyPairRequest), 2u);
  // The host resolves the TrustList through GetTrustList for its LastUpdateTime check and again for the
  // download: two calls for one refresh. A refresh per type would add the second type's check (three).
  EXPECT_EQ(mGds->call_count(GdsMethod::GetTrustList), 2u) << "the group's TrustList is refreshed once";
  const auto issued = mGds->issued_certificates(applicationId);
  ASSERT_EQ(issued.size(), 2u);
  const auto heldRsa = held_certificate(CertificateType::RsaSha256Application);
  const auto heldEcc = held_certificate(CertificateType::EccNistP256Application);
  ASSERT_NE(heldRsa, nullptr);
  ASSERT_NE(heldEcc, nullptr) << "the ECC certificate is held beside the RSA one";
  EXPECT_EQ(heldEcc->key_algorithm(), CertificateKeyAlgorithm::EccNistP256);
}

// PULL-9 (CL-PULLCRT-001/002, OPC 10000-12 7.6): the GDS channel is SignAndEncrypt, and a configuration that
// asks for less does not weaken it. The emulator, like a conformant GDS, refuses the certificate Methods on a
// channel that is not encrypted, so a cycle that provisions with Sign requested proves the channel stayed
// encrypted. Falsifiable: a manager that honoured the override would be refused by the GDS and commit
// nothing.
// @relation(AC-CL-PULLCRT-001-THE-PULLCERTIFICATEMANAGER-S-GDS-CHANNEL, scope=function)
TEST_F(GdsPullProvisioning, ARequestToWeakenTheGdsChannelIsRefusedAndTheChannelStaysEncrypted)
{
  const NodeId applicationId = register_application();
  ASSERT_FALSE(applicationId.is_null());
  auto config = pull_config(applicationId);
  config.requestedGdsSecurityMode = MessageSecurityMode::Sign;
  client::CertificateGroupConfig group;
  group.certificateRequest = make_csr(mInstallKeys);
  config.certificateGroups.push_back(std::move(group));
  start(std::move(config));
  run_cycle();

  const auto info = mManager->pull_cert_info();
  ASSERT_TRUE(info->lastCertCommitAt.has_value())
    << "the cycle ran over an encrypted channel: "
    << (info->lastError ? ua::to_string(*info->lastError) : std::string{"no error"});
  EXPECT_EQ(mGds->issued_certificates(applicationId).size(), 1u);
}
