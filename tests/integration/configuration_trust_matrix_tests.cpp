// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Wave A of the configuration coverage matrix - trust, PKI and certificate validation
///        (configuration coverage matrix section 4).
///
/// Every test here sets ONE `FileTrustListConfig` field to a non-default value and asserts a
/// difference a peer can observe over a real secure channel. The fields decide whether a peer is
/// trusted, so a vacuous test here is worse than none: it reports that a trust control is exercised
/// when only its struct was copied.
///
/// WHY THESE SERVERS TAKE A NULL CERTIFICATE STORE. `ComplianceSecured` injects a pre-built store into
/// `Server::create`, which is convenient and bypasses the configuration entirely - the trust-list paths
/// are never read. Passing `nullptr` instead is what makes `ServerImpl` build its own store from
/// `file_trust_list_configuration()` (`ua_server_impl.cpp:3426`), which is the production path and the
/// only one under which these fields mean anything.
///
/// THE CONTROL IS ALWAYS A SECOND SERVER, not a second assertion. Each row stands up two servers that
/// differ in exactly the field under test and drives the same client connect at both. That is what makes
/// the row falsifiable: a server that ignores the field answers both connects identically.

#include <fmt/ranges.h>

#include "ua_byte_format.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "test_pki_helpers.h"
#include "test_utilities.h"

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_crypto.h"
#include "ua_easy_connect_policy.h"
#include "ua_endpoint_description.h"
#include "ua_fmt.h"
#include "ua_guid.h"
#include "ua_method_id.h"
#include "ua_object_id.h"
#include "ua_server.h"
#include "ua_server_authentication.h"
#include "ua_status.h"
#include "ua_typed_access.h"
#include "ua_variable_id.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

// The SAN entries every certificate here carries. A HostName absent from the server certificate is a
// separate row (`relaxHostNameCheck`), so these must always match the loopback the listener binds.
constexpr std::string_view serverUri{"urn:test:cfgtrust:server"};
constexpr std::string_view clientUri{"urn:test:cfgtrust:client"};

// A self-signed application-instance certificate plus its keys. Wave A's rows turn on WHICH store holds
// WHICH certificate, so every identity is allocated separately and placed by hand.
struct Party
{
  std::shared_ptr<const AsymmetricKeyPair> keys;
  std::shared_ptr<const X509Certificate> cert;
};

// @p expiry is the notAfter; validity always starts at issuance, so an expiry in the PAST yields an
// already-expired certificate - which is how the validation-options row gets a certificate that is
// trusted and still invalid. Allocating through the SDK's own application-certificate call (rather than
// hand-built parameters) is what guarantees the keyUsage bits an application instance certificate needs.
Party allocate(const std::shared_ptr<const Crypto>& crypto, std::string_view commonName, std::string_view uri,
  std::vector<std::string> hostnames = {"localhost", "127.0.0.1"},
  UtcTime expiry = UtcTime{2050, 1, 1, 0, 0, 0})
{
  Crypto::Name subject;
  subject.commonName = std::string{commonName};
  Crypto::SubjectAlternateName san;
  san.uris.push_back(std::string{uri});
  san.hostnames = std::move(hostnames);

  auto result = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, expiry, san, CertificateType::RsaSha256Application, 2048);
  EXPECT_TRUE(result.is_good()) << to_string(result.status_code());
  auto [keys, cert] = std::move(result).value();
  return Party{std::move(keys), std::move(cert)};
}

// A self-signed User Certificate for an X509 identity token. OPC 10000-6 Table 44: "The cA flag shall be
// FALSE for User Certificates. The pathLength shall not be present", and keyUsage carries
// digitalSignature. An application instance certificate is not a User Certificate (its usages and SAN are the
// application's), so only its key pair is kept and the certificate is re-issued as a User Certificate. An
// @p expired certificate's validity ended yesterday, so it is trusted and still invalid.
Party allocate_user(const std::shared_ptr<const Crypto>& crypto, std::string_view commonName,
  std::string_view uri, bool expired = false)
{
  const Party keySource = allocate(crypto, commonName, uri);

  Crypto::CreateCertificateConfig parameters;
  parameters.serialNumber = "1";
  parameters.subject.commonName = std::string{commonName};
  parameters.subjectKeys = keySource.keys;
  parameters.issuerKeys = keySource.keys;
  parameters.certificateSignatureAlgorithm = CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
  parameters.basicConstraint.cA = false;
  parameters.keyUsage.digitalSignature = true;
  parameters.keyUsage.nonRepudiation = true;
  parameters.subjectAlternateName.uris = {std::string{uri}};
  const auto now = DateTime::now().value();
  parameters.from = DateTime{now - std::chrono::days{expired ? 2 : 1}};
  parameters.to = DateTime{expired ? now - std::chrono::days{1} : now + std::chrono::days{3650}};
  return Party{keySource.keys, TestPki{crypto}.create_cert(parameters)};
}

// Builds a store over @p path and seeds it, then lets it go: the SERVER reopens the same directory from
// its own configuration. Seeding through a throwaway store rather than writing files by hand keeps the
// on-disk layout the store's business.
void seed_store(const std::filesystem::path& path, const boost::asio::any_io_executor& executor,
  const std::shared_ptr<const Crypto>& crypto, const Party& own,
  const std::vector<std::shared_ptr<const X509Certificate>>& trusted)
{
  std::filesystem::create_directories(path);
  auto store = CertificateStoreFiles::create(executor, crypto, {.trustListPath = path});

  CertificateStore::ApplicationCertificate appCert;
  appCert.certificateType = CertificateType::RsaSha256Application;
  appCert.certificate = own.cert;
  appCert.keys = own.keys;
  store->add_to_application_certificates_sync(appCert);

  for (const auto& certificate : trusted)
    store->add_to_trusted_certificates_sync(certificate);
}

// The password every store in this file uses. `CertificateStoreFiles` encrypts private keys, so the
// server must reopen a seeded directory under the same credential the seeding store used.
std::shared_ptr<const Crypto> create_test_crypto()
{
  return create_default_crypto([]() { return ua::SecureString{"password"}; });
}

// A server whose certificate store is built by ServerImpl FROM THE CONFIGURATION, exposing one
// Basic256Sha256/Sign endpoint. Holds its own pool so several can run at once in a single test.
class ConfiguredServer
{
public:
  // @p configure receives the ApplicationConfig before the Server is created; a row mutates the
  // one FileTrustListConfig field it is testing and nothing else.
  // @p withNoneEndpoint additionally exposes an unsecured endpoint, so a row can make an easy-connect
  // ranker choose between a secured and an unsecured offer from ONE server.
  ConfiguredServer(std::shared_ptr<const Crypto> crypto,
    const std::function<void(ApplicationConfig&)>& configure, bool withNoneEndpoint = false)
  {
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = std::string{serverUri};
    configure(appCfg);

    ServerComponents components{
      .crypto = std::move(crypto), .logSink = test_log_sink(), .logLevel = LogLevel::Debug};
    components.authenticator = std::make_shared<AnonymousAuthenticator>();
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}});

    server::CreateConfig createCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

    // The null store is the point: ServerImpl builds one from the trust-list configuration above.
    mServer.emplace(Server::create(mPool.executor(), std::move(createCfg), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListener = mServer->listen_sync(std::move(bind), {});

    ServerEndpointConfig signEp;
    signEp.name = "Basic256Sha256_Sign";
    signEp.messageSecurityMode = MessageSecurityMode::Sign;
    signEp.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    signEp.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListener, std::move(signEp));

    if (withNoneEndpoint)
    {
      ServerEndpointConfig noneEp;
      noneEp.name = "None";
      noneEp.messageSecurityMode = MessageSecurityMode::None;
      noneEp.securityPolicyId = SecurityPolicyId::None;
      noneEp.userIdentityTokens.push_back(
        create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
      mServer->add_endpoint(mListener, std::move(noneEp));
    }

    mServer->start_sync();
    const auto urls = mServer->advertised_urls(mListener);
    EXPECT_FALSE(urls.empty());
    if (!urls.empty())
      mEndpointUrl = urls.front().str();
  }

  ~ConfiguredServer()
  {
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mPool, "cfgtrust-server");
  }

  ConfiguredServer(const ConfiguredServer&) = delete;
  ConfiguredServer& operator=(const ConfiguredServer&) = delete;

  const std::string& endpoint_url() const
  {
    return mEndpointUrl;
  }

  Server& server()
  {
    return *mServer;
  }

private:
  boost::asio::thread_pool mPool;
  std::optional<Server> mServer;
  ListenerHandle mListener{0};
  std::string mEndpointUrl;
};

// ---------------------------------------------------------------------------------------------
// ConfigurationTrust: the client half. One client, one store, reused across the two servers a row
// stands up, so the only thing that differs between the subject connect and the control connect is the
// server-side configuration field under test.
// ---------------------------------------------------------------------------------------------
class ConfigurationTrust : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_test_crypto();
    mPkiRoot =
      std::filesystem::temp_directory_path() / ("ua_cfg_trust_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mPkiRoot);

    mServerParty = allocate(mCrypto, "ConfigurationTrust Server", serverUri);
    mClientParty = allocate(mCrypto, "ConfigurationTrust Client", clientUri);
    mStrangerParty = allocate(mCrypto, "ConfigurationTrust Stranger", "urn:test:cfgtrust:stranger");

    // The client trusts the server certificate in every row here; what varies is whether the SERVER
    // trusts the client, so a failed connect can only mean the server's trust list.
    const auto clientStorePath = mPkiRoot / "client_store";
    seed_store(clientStorePath, mClientPool.executor(), mCrypto, mClientParty, {mServerParty.cert});
    mClientStore =
      CertificateStoreFiles::create(mClientPool.executor(), mCrypto, {.trustListPath = clientStorePath});

    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = std::string{clientUri};
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
    mClient.emplace(Client::create(mClientPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mClientStore,
        .logSink = mClientLogSink,
        .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    mClient.reset();
    mExtraStores.clear();
    mClientStore.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientPool, "cfgtrust-client");
    std::error_code ec;
    std::filesystem::remove_all(mPkiRoot, ec);
  }

  // A Sign connect to @p url under the client identity. Returns the ConnectResult so a row can assert
  // either half; the server certificate is supplied so no discovery round trip is needed.
  Client::ConnectResult connect_to(const std::string& url)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = url;
    config.securityMode = MessageSecurityMode::Sign;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mServerParty.cert;
    return mClient->try_connect_sync(std::move(config));
  }

  // An additional client with its OWN certificate, so a row can present several distinct untrusted
  // identities to one server. Each gets a private store directory; all of them trust the server, so a
  // refusal is always the server's decision about the client and never the reverse.
  Client make_extra_client(const Party& party, std::string_view uri, std::string_view storeName)
  {
    const auto path = mPkiRoot / std::string{storeName};
    seed_store(path, mClientPool.executor(), mCrypto, party, {mServerParty.cert});
    auto store = CertificateStoreFiles::create(mClientPool.executor(), mCrypto, {.trustListPath = path});
    mExtraStores.push_back(store);

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = std::string{uri};
    client::CreateConfig cfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    return Client::create(mClientPool.executor(),
      std::move(cfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = std::move(store),
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});
  }

  // The certificates the server has recorded as rejected, read from the store the server itself built.
  std::vector<std::shared_ptr<const X509Certificate>> rejected_list(ConfiguredServer& server)
  {
    auto result =
      server.server().default_application_group_certificate_store().try_get_rejected_certificates_sync();
    EXPECT_TRUE(result.is_good()) << to_string(result.status_code());
    return result.is_good() ? std::move(result).value()
                            : std::vector<std::shared_ptr<const X509Certificate>>{};
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::filesystem::path mPkiRoot;
  // Client-side log capture: one row asserts that a tolerated certificate mismatch is still REPORTED.
  std::shared_ptr<CapturingLogSink> mClientLogSink{std::make_shared<CapturingLogSink>()};
  std::vector<std::shared_ptr<CertificateStore>> mExtraStores;
  Party mServerParty;
  Party mClientParty;
  Party mStrangerParty;  // an identity no server under test ever trusts
  boost::asio::thread_pool mClientPool;
  std::shared_ptr<CertificateStore> mClientStore;
  std::optional<Client> mClient;
};

// Row: FileTrustListConfig::defaultApplicationGroupTrustListPath.
//
// Two directories, seeded with the SAME server application certificate and DIFFERENT trust lists: one
// trusts this client, the other trusts a stranger. The field names which directory the server opens, so
// pointing it at the first admits the client and pointing it at the second rejects it. Ignoring the
// field (or defaulting to `./pki/own`, which holds neither certificate) cannot produce this split - the
// server would answer both connects the same way.
//
// The matrix row describes the stimulus as a CA that signed the client certificate. A self-signed client
// certificate in the trusted list proves the same thing - which directory the server read - without
// making the oracle depend on chain-building behaviour that is a separate concern.
// @relation(AC-SVR-TCP-032-TRUSTLIST, scope=function)
TEST_F(ConfigurationTrust, ApplicationGroupTrustListPathSelectsTheStoreTheServerReads)
{
  const auto trustingPath = mPkiRoot / "trusts_client";
  const auto strangerPath = mPkiRoot / "trusts_stranger";
  seed_store(trustingPath, mClientPool.executor(), mCrypto, mServerParty, {mClientParty.cert});
  seed_store(strangerPath, mClientPool.executor(), mCrypto, mServerParty, {mStrangerParty.cert});

  {
    ConfiguredServer trusting{mCrypto,
      [&](ApplicationConfig& cfg)
      {
        cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = trustingPath;
      }};
    ASSERT_FALSE(trusting.endpoint_url().empty());

    auto connected = connect_to(trusting.endpoint_url());
    EXPECT_TRUE(connected.is_good())
      << "the configured directory holds this client's certificate, so the channel must open: "
      << to_string(connected.status_code());
    if (connected.is_good())
      std::move(connected).value().close_sync();
  }

  ConfiguredServer stranger{mCrypto,
    [&](ApplicationConfig& cfg)
    {
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = strangerPath;
    }};
  ASSERT_FALSE(stranger.endpoint_url().empty());

  auto rejected = connect_to(stranger.endpoint_url());
  EXPECT_EQ(rejected.status_code().as_status(), Status::BadSecurityChecksFailed)
    << "a server reading a trust list that does not hold this client must refuse the channel on trust "
       "grounds; a server that ignored the path would have admitted it exactly as the first one did";
  if (rejected.is_good())
    std::move(rejected).value().close_sync();
}

// Row: FileTrustListConfig::storeRejectedCertificates.
//
// A gate, so both halves are required: the ON case proves the rejected certificate is recorded, the OFF
// case proves the flag actually suppresses it. Asserting only that OFF is empty would pass against a
// server that never recorded anything at all - which is why the ON control runs against an otherwise
// identical server and must find exactly the certificate that was refused.
TEST_F(ConfigurationTrust, StoreRejectedCertificatesGatesTheRejectedList)
{
  // Neither server trusts this client; the connect below is refused by both. What differs is whether the
  // refusal is recorded.
  const auto trustPath = mPkiRoot / "rejects_client";
  seed_store(trustPath, mClientPool.executor(), mCrypto, mServerParty, {mStrangerParty.cert});

  {
    ConfiguredServer recording{mCrypto,
      [&](ApplicationConfig& cfg)
      {
        cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = trustPath;
        cfg.file_trust_list_configuration().storeRejectedCertificates = true;  // the default
      }};
    ASSERT_FALSE(recording.endpoint_url().empty());

    auto refused = connect_to(recording.endpoint_url());
    ASSERT_TRUE(refused.is_bad()) << "precondition: this client is not trusted by either server";

    const auto rejected = rejected_list(recording);
    ASSERT_EQ(rejected.size(), 1u) << "the ON control must record the refused certificate, or the OFF "
                                      "half below proves nothing";
    EXPECT_EQ(to_string(rejected.front()->thumbprint()), to_string(mClientParty.cert->thumbprint()))
      << "the recorded certificate must be the one that was refused";
  }

  // Same trust list, same refusal - only the flag differs.
  const auto suppressedPath = mPkiRoot / "rejects_client_nostore";
  seed_store(suppressedPath, mClientPool.executor(), mCrypto, mServerParty, {mStrangerParty.cert});
  ConfiguredServer suppressing{mCrypto,
    [&](ApplicationConfig& cfg)
    {
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = suppressedPath;
      cfg.file_trust_list_configuration().storeRejectedCertificates = false;  // default true
    }};
  ASSERT_FALSE(suppressing.endpoint_url().empty());

  auto refused = connect_to(suppressing.endpoint_url());
  ASSERT_TRUE(refused.is_bad());

  EXPECT_TRUE(rejected_list(suppressing).empty())
    << "with storage off the refusal must leave no rejected entry; the control above shows this same "
       "refusal is recorded when the flag is on";
  EXPECT_FALSE(std::filesystem::exists(suppressedPath / "RejectedCertificates"))
    << "nor may it be written to disk";
}

// Row: FileTrustListConfig::maxRejectedCertificates.
//
// A pre-auth peer can present unlimited distinct certificates, so the bound is a DoS control. Three
// distinct untrusted clients are refused in a known order against a server that retains two: the set must
// be capped at two AND must hold the NEWEST two, since a cap that evicted newest-first would keep the
// list bounded while making it useless to the operator. The default of 100 would retain all three.
TEST_F(ConfigurationTrust, MaxRejectedCertificatesRetainsTheNewestWithinTheBound)
{
  const auto trustPath = mPkiRoot / "rejects_everyone";
  seed_store(trustPath, mClientPool.executor(), mCrypto, mServerParty, {mStrangerParty.cert});

  ConfiguredServer server{mCrypto,
    [&](ApplicationConfig& cfg)
    {
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = trustPath;
      cfg.file_trust_list_configuration().maxRejectedCertificates = 2;  // default 100
    }};
  ASSERT_FALSE(server.endpoint_url().empty());

  const Party second = allocate(mCrypto, "ConfigurationTrust Client 2", "urn:test:cfgtrust:client2");
  const Party third = allocate(mCrypto, "ConfigurationTrust Client 3", "urn:test:cfgtrust:client3");
  auto secondClient = make_extra_client(second, "urn:test:cfgtrust:client2", "client2_store");
  auto thirdClient = make_extra_client(third, "urn:test:cfgtrust:client3", "client3_store");

  // Oldest first, so the eviction order is known.
  auto first = connect_to(server.endpoint_url());
  ASSERT_TRUE(first.is_bad());

  const auto connectExtra = [&](Client& client)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = server.endpoint_url();
    config.securityMode = MessageSecurityMode::Sign;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mServerParty.cert;
    return client.try_connect_sync(std::move(config));
  };
  ASSERT_TRUE(connectExtra(secondClient).is_bad());
  ASSERT_TRUE(connectExtra(thirdClient).is_bad());

  const auto rejected = rejected_list(server);
  ASSERT_EQ(rejected.size(), 2u)
    << "three distinct certificates were refused under a bound of two; the default of 100 would hold all "
       "three";

  std::vector<std::string> thumbprints;
  thumbprints.reserve(rejected.size());
  for (const auto& certificate : rejected)
    thumbprints.push_back(to_string(certificate->thumbprint()));

  EXPECT_THAT(thumbprints,
    ::testing::UnorderedElementsAre(
      to_string(second.cert->thumbprint()), to_string(third.cert->thumbprint())))
    << "the retained set must be the NEWEST two: the first client's certificate is the one evicted";
}

// Row: FileTrustListConfig::trustListRefreshPeriod.
//
// The operator adds a certificate to the trust list of a RUNNING server. With a refresh period the server
// picks it up on its own; with `nullopt` it never does until restarted. Both halves are required - a
// server that reloaded unconditionally would pass the first half alone.
//
// Costs wall-clock: the subject waits out a real 1 s period (the store schedules a real timer), and the
// control waits the same span to show the addition is genuinely never seen rather than merely late.
TEST_F(ConfigurationTrust, TrustListRefreshPeriodReloadsWithoutRestart)
{
  constexpr auto refresh = 1s;
  // Long enough for at least one tick to land, with slack for a loaded box.
  constexpr auto observe = 4s;

  const auto refreshingPath = mPkiRoot / "refreshing";
  const auto staticPath = mPkiRoot / "static";
  seed_store(refreshingPath, mClientPool.executor(), mCrypto, mServerParty, {mStrangerParty.cert});
  seed_store(staticPath, mClientPool.executor(), mCrypto, mServerParty, {mStrangerParty.cert});

  // Adds the client to a trust list on disk, through a store the SERVER does not own. The server's own
  // store must notice the file, which is the whole point of the period.
  const auto trustClientOnDisk = [&](const std::filesystem::path& path)
  {
    auto editor = CertificateStoreFiles::create(mClientPool.executor(), mCrypto, {.trustListPath = path});
    editor->add_to_trusted_certificates_sync(mClientParty.cert);
  };

  {
    ConfiguredServer refreshing{mCrypto,
      [&](ApplicationConfig& cfg)
      {
        cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = refreshingPath;
        cfg.file_trust_list_configuration().trustListRefreshPeriod = refresh;
      }};
    ASSERT_FALSE(refreshing.endpoint_url().empty());

    ASSERT_TRUE(connect_to(refreshing.endpoint_url()).is_bad())
      << "precondition: the client is not trusted before the certificate is added";

    trustClientOnDisk(refreshingPath);
    std::this_thread::sleep_for(observe);

    auto admitted = connect_to(refreshing.endpoint_url());
    EXPECT_TRUE(admitted.is_good())
      << "a refreshing server must pick the added certificate up from disk with no restart: "
      << to_string(admitted.status_code());
    if (admitted.is_good())
      std::move(admitted).value().close_sync();
  }

  // Control: no period at all. The same edit, the same wait, and the server must still refuse.
  ConfiguredServer never{mCrypto,
    [&](ApplicationConfig& cfg)
    {
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = staticPath;
      cfg.file_trust_list_configuration().trustListRefreshPeriod = std::nullopt;
    }};
  ASSERT_FALSE(never.endpoint_url().empty());
  ASSERT_TRUE(connect_to(never.endpoint_url()).is_bad());

  trustClientOnDisk(staticPath);
  std::this_thread::sleep_for(observe);

  auto stillRefused = connect_to(never.endpoint_url());
  EXPECT_TRUE(stillRefused.is_bad())
    << "with no refresh period the on-disk addition must NOT take effect in a running server; the "
       "subject above shows the same edit is picked up when a period is configured";
  if (stillRefused.is_good())
    std::move(stillRefused).value().close_sync();
}

// Row: ConnectionConfig::relaxHostNameCheck.
//
// A gate on the CLIENT, so both halves are required. The server presents a certificate whose SAN covers
// `localhost` but NOT the loopback IP the listener actually advertises, so the CreateSession endpointUrl
// HostName cannot be matched. Default (false) closes the channel with `Bad_CertificateHostNameInvalid`;
// true completes the connect and reports the mismatch as a warning instead - tolerated, not silent, which
// is the part that makes the relaxed mode defensible.
TEST_F(ConfigurationTrust, RelaxHostNameCheckGatesTheEndpointHostNameMismatch)
{
  // No "127.0.0.1" in the SAN, so the advertised loopback URL cannot match this certificate.
  const Party mismatched =
    allocate(mCrypto, "ConfigurationTrust Mismatched Server", serverUri, {"localhost"});
  mClientStore->add_to_trusted_certificates_sync(mismatched.cert);

  const auto trustPath = mPkiRoot / "hostname_mismatch";
  seed_store(trustPath, mClientPool.executor(), mCrypto, mismatched, {mClientParty.cert});

  ConfiguredServer server{mCrypto,
    [&](ApplicationConfig& cfg)
    {
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = trustPath;
    }};
  ASSERT_FALSE(server.endpoint_url().empty());
  ASSERT_NE(server.endpoint_url().find("127.0.0.1"), std::string::npos)
    << "the row depends on the advertised URL naming a host the certificate does not cover";

  const auto connectWith = [&](bool relax)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = server.endpoint_url();
    config.securityMode = MessageSecurityMode::Sign;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mismatched.cert;
    config.relaxHostNameCheck = relax;
    return mClient->try_connect_sync(std::move(config));
  };

  auto strict = connectWith(false);  // the default
  EXPECT_EQ(strict.status_code().as_status(), Status::BadCertificateHostNameInvalid)
    << "the default must refuse a certificate that does not cover the endpoint HostName";
  if (strict.is_good())
    std::move(strict).value().close_sync();

  mClientLogSink->clear();
  auto relaxed = connectWith(true);
  EXPECT_TRUE(relaxed.is_good()) << "with the check relaxed the same connect must complete: "
                                 << to_string(relaxed.status_code());
  if (relaxed.is_good())
    std::move(relaxed).value().close_sync();

  const auto records = mClientLogSink->records();
  EXPECT_TRUE(std::any_of(records.begin(),
    records.end(),
    [](const CapturingLogSink::Entry& entry)
    {
      return entry.level <= ua::LogLevel::Warning &&
             entry.message.find("HostName mismatch") != std::string::npos;
    }))
    << "relaxing the check must still REPORT the mismatch; a silently accepted mismatch is the failure "
       "mode this half exists to catch";
}

// Row: ConnectionConfig::trustStoreOverride.
//
// Bootstrap trust: the client's runtime store does not trust this server, and an override store supplied
// on the connect does. Both halves run against the SAME server, so the difference is the override alone -
// with it the channel opens, without it the client refuses the server's certificate.
//
// NOT covered here: the matrix's second, regression-critical oracle - that a RECONNECTED channel still
// validates against the override rather than silently reverting to the runtime store. That needs the
// reconnect harness Wave F builds, and is tracked as its own row rather than assumed.
TEST_F(ConfigurationTrust, TrustStoreOverrideSuppliesTrustTheRuntimeStoreLacks)
{
  // Deliberately never added to mClientStore: the runtime store must not be able to validate this.
  const Party untrusted = allocate(mCrypto, "ConfigurationTrust Override Server", serverUri);

  const auto serverPath = mPkiRoot / "override_server";
  seed_store(serverPath, mClientPool.executor(), mCrypto, untrusted, {mClientParty.cert});

  ConfiguredServer server{mCrypto,
    [&](ApplicationConfig& cfg)
    {
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = serverPath;
    }};
  ASSERT_FALSE(server.endpoint_url().empty());

  const auto overridePath = mPkiRoot / "override_store";
  seed_store(overridePath, mClientPool.executor(), mCrypto, mClientParty, {untrusted.cert});
  auto overrideStore =
    CertificateStoreFiles::create(mClientPool.executor(), mCrypto, {.trustListPath = overridePath});

  const auto connectWith = [&](std::shared_ptr<CertificateStore> overrideStore)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = server.endpoint_url();
    config.securityMode = MessageSecurityMode::Sign;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = untrusted.cert;
    config.trustStoreOverride = std::move(overrideStore);
    return mClient->try_connect_sync(std::move(config));
  };

  // Note the asymmetry with the server-side rows above: a server refusing an untrusted client reports the
  // masked pre-auth `Bad_SecurityChecksFailed`, whereas a client refusing an untrusted server has no
  // reason to withhold detail and reports `Bad_CertificateUntrusted`.
  auto withoutOverride = connectWith(nullptr);  // the default
  EXPECT_EQ(withoutOverride.status_code().as_status(), Status::BadCertificateUntrusted)
    << "the runtime store does not hold this server's certificate, so the default must refuse it";
  if (withoutOverride.is_good())
    std::move(withoutOverride).value().close_sync();

  auto withOverride = connectWith(overrideStore);
  EXPECT_TRUE(withOverride.is_good())
    << "the override store holds the server certificate, so the same connect must succeed: "
    << to_string(withOverride.status_code());
  if (withOverride.is_good())
    std::move(withOverride).value().close_sync();
}

// Row: FileTrustListConfig::defaultApplicationGroupTrustListValidationOptions.
//
// One certificate, two servers, one option bit. The client presents an EXPIRED certificate that both
// servers hold in their trust lists, so the only thing that can decide the outcome is whether
// `SuppressCertificateExpired` is set. Default (no bits) refuses it; the suppressing server admits it.
// Expiry is the right lever precisely because it is checked independently of trust: the certificate is
// trusted in both halves and still refused in one.
TEST_F(ConfigurationTrust, ApplicationGroupValidationOptionsDecideAnExpiredPeerCertificate)
{
  // notAfter in the past: trusted by both servers below, and expired for both.
  const Party expired = allocate(mCrypto,
    "ConfigurationTrust Expired Client",
    "urn:test:cfgtrust:expired",
    {"localhost", "127.0.0.1"},
    UtcTime{2020, 1, 1, 0, 0, 0});

  auto expiredClient = make_extra_client(expired, "urn:test:cfgtrust:expired", "expired_store");

  const auto connectToUrl = [&](const std::string& url)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = url;
    config.securityMode = MessageSecurityMode::Sign;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mServerParty.cert;
    return expiredClient.try_connect_sync(std::move(config));
  };

  // Strict: the certificate is trusted but expired, so validation must reject it.
  {
    const auto strictPath = mPkiRoot / "options_strict";
    seed_store(strictPath, mClientPool.executor(), mCrypto, mServerParty, {expired.cert});
    ConfiguredServer strict{mCrypto,
      [&](ApplicationConfig& cfg)
      {
        cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = strictPath;
        cfg.file_trust_list_configuration().defaultApplicationGroupTrustListValidationOptions =
          TrustListValidationOptions{};  // the default: suppress nothing
      }};
    ASSERT_FALSE(strict.endpoint_url().empty());

    auto refused = connectToUrl(strict.endpoint_url());
    EXPECT_TRUE(refused.is_bad()) << "an expired certificate must not be admitted when nothing is suppressed";
    if (refused.is_good())
      std::move(refused).value().close_sync();
  }

  // Tolerant: same certificate, same trust list, one bit set.
  const auto tolerantPath = mPkiRoot / "options_tolerant";
  seed_store(tolerantPath, mClientPool.executor(), mCrypto, mServerParty, {expired.cert});
  ConfiguredServer tolerant{mCrypto,
    [&](ApplicationConfig& cfg)
    {
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = tolerantPath;
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListValidationOptions =
        TrustListValidationOptions{{TrustListValidationOptions::Bit::SuppressCertificateExpired}};
    }};
  ASSERT_FALSE(tolerant.endpoint_url().empty());

  auto admitted = connectToUrl(tolerant.endpoint_url());
  EXPECT_TRUE(admitted.is_good())
    << "with SuppressCertificateExpired set the same expired certificate must be admitted, which is "
       "what proves the options field reached the store: "
    << to_string(admitted.status_code());
  if (admitted.is_good())
    std::move(admitted).value().close_sync();
}

// Row: EasyConnectConfig::allowAnonymousFirstConnect.
//
// A security gate, so both halves are required. The server offers BOTH an unsecured and a secured
// endpoint, and the row supplies a ranker that deliberately picks the unsecured one - the situation the
// flag exists to police, since silently accepting an unsecured winner while security was on offer is a
// downgrade. Default (false) refuses before any session is created; true permits the bootstrap connect.
//
// The ranker is what makes this deterministic: the default ranker prefers the secured endpoint, so
// without it the unsecured branch is never reached and the row would pass vacuously.
TEST_F(ConfigurationTrust, AllowAnonymousFirstConnectGatesAnUnsecuredWinner)
{
  const auto trustPath = mPkiRoot / "easy_connect";
  seed_store(trustPath, mClientPool.executor(), mCrypto, mServerParty, {mClientParty.cert});

  ConfiguredServer server{mCrypto,
    [&](ApplicationConfig& cfg)
    { cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = trustPath; },
    /*withNoneEndpoint=*/true};
  ASSERT_FALSE(server.endpoint_url().empty());

  const auto easyConnectWith = [&](bool allow)
  {
    ua::client::EasyConnectConfig policy;
    policy.endpointUrl = server.endpoint_url();
    policy.allowAnonymousFirstConnect = allow;
    // Score the unsecured offer highest, so the winner is the one the gate is about.
    policy.ranker = [](const ua::EndpointDescription& endpoint)
    {
      return endpoint.security_mode() == MessageSecurityMode::None ? 100 : 1;
    };
    return mClient->try_easy_connect_sync(std::move(policy));
  };

  auto refused = easyConnectWith(false);  // the default
  EXPECT_TRUE(refused.is_bad())
    << "with the gate closed an unsecured winner must be refused while the server still offers security";
  if (refused.is_good())
    std::move(refused).value().close_sync();

  auto permitted = easyConnectWith(true);
  EXPECT_TRUE(permitted.is_good()) << "opting in must permit the same bootstrap connect: "
                                   << to_string(permitted.status_code());
  if (permitted.is_good())
    std::move(permitted).value().close_sync();
}

// ---------------------------------------------------------------------------------------------
// ConfigurationUserTokenTrust: the user-token half of FileTrustListConfig.
//
// These rows turn on WHOSE X.509 USER certificate the server will activate a session for. The
// application-instance trust is held constant and permissive across every server here, so a refused
// ActivateSession can only mean the user-token trust list; a refused OpenSecureChannel would be a
// different failure and shows up as a different status.
//
// The authenticator is deliberately constructed WITHOUT a store. That is the arrangement the
// configuration exists for: the application cannot hand a server-owned store to an authenticator it
// builds before the Server, so the store arrives per request on AuthnRequest.
// ---------------------------------------------------------------------------------------------

constexpr std::string_view userTokenPolicyId{"cfgtrust_x509"};
constexpr std::string_view userNameTokenPolicyId{"cfgtrust_username"};
// Not for production: a compiled-in credential. The rows that use it need an AuthenticatedUser session
// whose existence does not depend on the user-token certificate trust list, because that list is their
// subject.
constexpr std::string_view adminUser{"cfgtrust-admin"};
constexpr std::string_view adminPassword{"cfgtrust-admin-secret"};

// Server offering ONE Basic256Sha256/SignAndEncrypt endpoint with an Anonymous and a Certificate
// user-token policy. SignAndEncrypt because the Part 12 TrustList Methods one row calls refuse
// anything less.
class UserTokenServer
{
public:
  UserTokenServer(const std::shared_ptr<const Crypto>& crypto,
    const std::function<void(ApplicationConfig&)>& configure,
    std::shared_ptr<CertificateStore> userTokenStoreHook = nullptr)
  {
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.application_description_part().applicationUri = std::string{serverUri};
    // create_test_config seeds a user-token path for every test server; a row that is about the
    // UNSET case needs it gone before `configure` gets its say.
    appCfg.file_trust_list_configuration().defaultUserTokenGroupTrustListPath.reset();
    configure(appCfg);

    ServerComponents components{.crypto = crypto, .logSink = test_log_sink(), .logLevel = LogLevel::Debug};
    auto composite = std::make_shared<CompositeAuthenticator>();
    composite->add(UserTokenKind::Anonymous, std::make_shared<AnonymousAuthenticator>());
    composite->add(UserTokenKind::X509, std::make_shared<X509UserAuthenticator>());
    // A username identity as well as an X.509 one. The rows about which certificate groups a server
    // publishes need a SecurityAdmin session - the standard NodeSet grants that subtree to SecurityAdmin
    // alone - and one of those rows runs against a server with NO user-token trust list, where by
    // construction no X.509 user can authenticate. Username authentication does not depend on that store,
    // so it is the only identity that reaches AuthenticatedUser on both servers under test.
    composite->add(UserTokenKind::UserName,
      std::make_shared<SimpleUserPasswordAuthenticator>(
        [](std::string_view username, const ua::SecureString& password)
        { return username == adminUser && std::string_view{password.c_str()} == adminPassword; }));
    components.authenticator = std::move(composite);
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::AuthenticatedUser}});
    components.userTokenCertificateStore = std::move(userTokenStoreHook);

    server::CreateConfig createCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};

    mServer.emplace(Server::create(mPool.executor(), std::move(createCfg), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListener = mServer->listen_sync(std::move(bind), {});

    ServerEndpointConfig endpoint;
    endpoint.name = "Basic256Sha256_SignAndEncrypt";
    endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    UserTokenPolicy certificatePolicy;
    certificatePolicy.token_type() = UserTokenType::Certificate;
    certificatePolicy.policy_id() = std::string{userTokenPolicyId};
    certificatePolicy.security_policy_uri() =
      std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};
    endpoint.userIdentityTokens.push_back(std::move(certificatePolicy));
    UserTokenPolicy userNamePolicy;
    userNamePolicy.token_type() = UserTokenType::UserName;
    userNamePolicy.policy_id() = std::string{userNameTokenPolicyId};
    userNamePolicy.security_policy_uri() =
      std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};
    endpoint.userIdentityTokens.push_back(std::move(userNamePolicy));
    mServer->add_endpoint(mListener, std::move(endpoint));

    mServer->start_sync();
    const auto urls = mServer->advertised_urls(mListener);
    EXPECT_FALSE(urls.empty());
    if (!urls.empty())
      mEndpointUrl = urls.front().str();
  }

  ~UserTokenServer()
  {
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mPool, "cfgusertoken-server");
  }

  UserTokenServer(const UserTokenServer&) = delete;
  UserTokenServer& operator=(const UserTokenServer&) = delete;

  const std::string& endpoint_url() const
  {
    return mEndpointUrl;
  }

private:
  boost::asio::thread_pool mPool;
  std::optional<Server> mServer;
  ListenerHandle mListener{0};
  std::string mEndpointUrl;
};

class ConfigurationUserTokenTrust : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_test_crypto();
    mPkiRoot = std::filesystem::temp_directory_path() /
               ("ua_cfg_usertoken_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mPkiRoot);

    mServerParty = allocate(mCrypto, "UserTokenTrust Server", serverUri);
    mClientParty = allocate(mCrypto, "UserTokenTrust Client", clientUri);
    mUserAlice = allocate_user(mCrypto, "UserTokenTrust Alice", "urn:test:cfgtrust:user:alice");
    mUserBob = allocate_user(mCrypto, "UserTokenTrust Bob", "urn:test:cfgtrust:user:bob");

    // The APPLICATION trust list every server here opens: it trusts the client application, so the
    // secure channel always succeeds and only the user token can fail.
    mApplicationStorePath = mPkiRoot / "server_app_store";
    seed_store(mApplicationStorePath, mClientPool.executor(), mCrypto, mServerParty, {mClientParty.cert});

    const auto clientStorePath = mPkiRoot / "client_store";
    seed_store(clientStorePath, mClientPool.executor(), mCrypto, mClientParty, {mServerParty.cert});
    mClientStore =
      CertificateStoreFiles::create(mClientPool.executor(), mCrypto, {.trustListPath = clientStorePath});

    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = std::string{clientUri};
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)};
    mClient.emplace(Client::create(mClientPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mClientStore,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    mClient.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientPool, "cfgusertoken-client");
    std::error_code ec;
    std::filesystem::remove_all(mPkiRoot, ec);
  }

  // Creates a user-token trust list at @p name holding @p trusted, and returns its path. No
  // application certificate: a user-token store never issues one.
  std::filesystem::path seed_user_store(std::string_view name,
    const std::vector<std::shared_ptr<const X509Certificate>>& trusted,
    TrustListValidationOptions options = TrustListValidationOptions{})
  {
    const auto path = mPkiRoot / std::string{name};
    std::filesystem::create_directories(path);
    auto store = CertificateStoreFiles::create(
      mClientPool.executor(), mCrypto, {.trustListPath = path, .validationOptions = options});
    for (const auto& certificate : trusted)
      store->add_to_trusted_certificates_sync(certificate);
    return path;
  }

  // The base configuration every row starts from: application trust held constant, user-token trust
  // left to the row.
  std::function<void(ApplicationConfig&)> base_config(std::optional<std::filesystem::path> userTokenPath,
    TrustListValidationOptions userTokenOptions = TrustListValidationOptions{}) const
  {
    return [this, userTokenPath = std::move(userTokenPath), userTokenOptions](ApplicationConfig& cfg)
    {
      cfg.file_trust_list_configuration().defaultApplicationGroupTrustListPath = mApplicationStorePath;
      cfg.file_trust_list_configuration().defaultUserTokenGroupTrustListPath = userTokenPath;
      cfg.file_trust_list_configuration().defaultUserTokenGroupTrustListValidationOptions = userTokenOptions;
    };
  }

  // Connect to @p url as a SecurityAdmin.
  //
  // The standard NodeSet declares `<RolePermission Permissions="65423">i=15704</RolePermission>` -
  // SecurityAdmin, and nothing else - on every certificate-group node (i=14156 DefaultApplicationGroup,
  // i=14088 DefaultHttpsGroup, i=14122 DefaultUserTokenGroup) and on their TrustList and CertificateTypes
  // children. An anonymous session holds no Browse permission there, so a Browse correctly returns nothing
  // and a row asserting "this group is not published" would pass over a surface it simply cannot see. This
  // fixture grants SecurityAdmin to AuthenticatedUser.
  //
  // Username rather than X.509 on purpose: one of the rows runs against a server configured with NO
  // user-token trust list, where by construction no X.509 user can authenticate. That list is the row's
  // subject, so the session used to observe it must not depend on it.
  Client::ConnectResult connect_as_security_admin(const std::string& url)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = url;
    config.securityMode = MessageSecurityMode::SignAndEncrypt;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mServerParty.cert;
    config.identity =
      UsernamePasswordIdentity{.username = std::string{adminUser}, .password = std::string{adminPassword}};
    config.userTokenPolicyId = std::string{userNameTokenPolicyId};
    return mClient->try_connect_sync(std::move(config));
  }

  // Connect to @p url presenting @p user as the X.509 user identity.
  Client::ConnectResult connect_as(const std::string& url, const Party& user)
  {
    ua::client::ConnectionConfig config;
    config.endpointUrl = url;
    config.securityMode = MessageSecurityMode::SignAndEncrypt;
    config.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    config.serverCertificate = mServerParty.cert;
    config.identity = X509Identity{.certificate = user.cert, .keyPair = user.keys};
    config.userTokenPolicyId = std::string{userTokenPolicyId};
    return mClient->try_connect_sync(std::move(config));
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::filesystem::path mPkiRoot;
  std::filesystem::path mApplicationStorePath;
  Party mServerParty;
  Party mClientParty;
  Party mUserAlice;
  Party mUserBob;
  boost::asio::thread_pool mClientPool;
  std::shared_ptr<CertificateStore> mClientStore;
  std::optional<Client> mClient;
};

// Row: FileTrustListConfig::defaultUserTokenGroupTrustListPath.
//
// Two servers identical but for this one path, pointed at two directories that trust DIFFERENT user
// certificates. The same client, the same application trust, the same endpoint: Alice activates
// against the directory that holds her certificate and is refused by the one that holds Bob's.
// A server that ignores the field answers both connects the same way, whichever way that is.
TEST_F(ConfigurationUserTokenTrust, UserTokenTrustListPathDecidesWhichUserCertificateActivates)
{
  const auto alicePath = seed_user_store("user_store_alice", {mUserAlice.cert});
  const auto bobPath = seed_user_store("user_store_bob", {mUserBob.cert});

  UserTokenServer trustsAlice{mCrypto, base_config(alicePath)};
  ASSERT_FALSE(trustsAlice.endpoint_url().empty());

  auto admitted = connect_as(trustsAlice.endpoint_url(), mUserAlice);
  EXPECT_TRUE(admitted.is_good()) << "the configured user-token trust list holds Alice's certificate, "
                                     "so her token must activate: "
                                  << to_string(admitted.status_code());
  if (admitted.is_good())
    std::move(admitted).value().close_sync();

  UserTokenServer trustsBob{mCrypto, base_config(bobPath)};
  ASSERT_FALSE(trustsBob.endpoint_url().empty());

  auto refused = connect_as(trustsBob.endpoint_url(), mUserAlice);
  EXPECT_TRUE(refused.is_bad())
    << "the same token must be refused by a server whose user-token trust list holds only Bob";
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadIdentityTokenRejected})
    << "an untrusted USER certificate is a token rejection, not a channel failure: "
    << to_string(refused.status_code());
  if (refused.is_good())
    std::move(refused).value().close_sync();
}

// Row: the OFF case for the same field.
//
// Unset must mean the server owns NO user-token store, not "fall back to a default directory". The
// control is the identical server with the path set: the only difference is whether the field carries
// a value, and that decides whether Alice can activate at all.
TEST_F(ConfigurationUserTokenTrust, UnsetUserTokenTrustListPathLeavesEveryCertificateTokenUntrusted)
{
  const auto alicePath = seed_user_store("off_case_alice", {mUserAlice.cert});

  UserTokenServer withoutStore{mCrypto, base_config(std::nullopt)};
  ASSERT_FALSE(withoutStore.endpoint_url().empty());

  auto refused = connect_as(withoutStore.endpoint_url(), mUserAlice);
  EXPECT_TRUE(refused.is_bad())
    << "with no user-token store configured there is nothing to establish trust against";
  EXPECT_EQ(refused.status_code(), StatusCode{Status::BadIdentityTokenRejected})
    << to_string(refused.status_code());
  if (refused.is_good())
    std::move(refused).value().close_sync();

  UserTokenServer withStore{mCrypto, base_config(alicePath)};
  ASSERT_FALSE(withStore.endpoint_url().empty());

  auto admitted = connect_as(withStore.endpoint_url(), mUserAlice);
  EXPECT_TRUE(admitted.is_good())
    << "setting the path is the only change, so it must be what admits the same token: "
    << to_string(admitted.status_code());
  if (admitted.is_good())
    std::move(admitted).value().close_sync();
}

// Row: FileTrustListConfig::defaultUserTokenGroupTrustListValidationOptions.
//
// Both servers open a user-token trust list holding the SAME expired user certificate, so trust is
// held constant and only the options bit differs. Strict refuses it; SuppressCertificateExpired
// admits it. A server that ignores the options field cannot produce the split.
TEST_F(ConfigurationUserTokenTrust, UserTokenValidationOptionsDecideAnExpiredUserCertificate)
{
  const Party expiredUser =
    allocate_user(mCrypto, "UserTokenTrust Expired User", "urn:test:cfgtrust:user:expired", true);

  const auto strictPath = seed_user_store("user_store_strict", {expiredUser.cert});
  UserTokenServer strict{mCrypto, base_config(strictPath, TrustListValidationOptions{})};
  ASSERT_FALSE(strict.endpoint_url().empty());

  auto refused = connect_as(strict.endpoint_url(), expiredUser);
  EXPECT_TRUE(refused.is_bad()) << "an expired user certificate must not activate when nothing is suppressed";
  if (refused.is_good())
    std::move(refused).value().close_sync();

  const auto tolerantPath = seed_user_store("user_store_tolerant", {expiredUser.cert});
  UserTokenServer tolerant{mCrypto,
    base_config(tolerantPath,
      TrustListValidationOptions{{TrustListValidationOptions::Bit::SuppressCertificateExpired}})};
  ASSERT_FALSE(tolerant.endpoint_url().empty());

  auto admitted = connect_as(tolerant.endpoint_url(), expiredUser);
  EXPECT_TRUE(admitted.is_good())
    << "with SuppressCertificateExpired set the same certificate must activate, which is what proves "
       "the user-token options reached the store: "
    << to_string(admitted.status_code());
  if (admitted.is_good())
    std::move(admitted).value().close_sync();
}

// Row: ServerComponents::userTokenCertificateStore.
//
// One owner per directory: when the host supplies a store the server must NOT also build one from the
// configured path. The two are seeded with different users, so which certificate activates says which
// store the authenticator was handed.
TEST_F(ConfigurationUserTokenTrust, SuppliedUserTokenStoreWinsOverTheConfiguredPath)
{
  const auto configuredPath = seed_user_store("hook_configured_bob", {mUserBob.cert});

  const auto hookPath = mPkiRoot / "hook_supplied_alice";
  std::filesystem::create_directories(hookPath);
  auto hookStore =
    CertificateStoreFiles::create(mClientPool.executor(), mCrypto, {.trustListPath = hookPath});
  hookStore->add_to_trusted_certificates_sync(mUserAlice.cert);

  UserTokenServer server{mCrypto, base_config(configuredPath), hookStore};
  ASSERT_FALSE(server.endpoint_url().empty());

  auto admitted = connect_as(server.endpoint_url(), mUserAlice);
  EXPECT_TRUE(admitted.is_good()) << "the supplied store trusts Alice, so her token must activate: "
                                  << to_string(admitted.status_code());
  if (admitted.is_good())
    std::move(admitted).value().close_sync();

  auto refused = connect_as(server.endpoint_url(), mUserBob);
  EXPECT_TRUE(refused.is_bad())
    << "Bob is trusted only by the CONFIGURED path; admitting him would mean the server opened that "
       "directory as well as taking the supplied store";
  if (refused.is_good())
    std::move(refused).value().close_sync();
}

// Part 12 section 7.10.6 requires a user-token TrustList change to re-evaluate affected X.509 Sessions
// while leaving Sessions authenticated by other means unaffected.
// @relation(AC-SVR-PULLCRT-018-TRUSTLIST-AFFECTS-USERS, scope=function)
TEST_F(ConfigurationUserTokenTrust, RemovingAUserCertificateOverPushClosesOnlyTheSessionsItInvalidates)
{
  const auto userPath = seed_user_store("push_user_store", {mUserAlice.cert});
  UserTokenServer server{mCrypto, base_config(userPath)};
  ASSERT_FALSE(server.endpoint_url().empty());

  auto aliceConnect = connect_as(server.endpoint_url(), mUserAlice);
  ASSERT_TRUE(aliceConnect.is_good()) << to_string(aliceConnect.status_code());
  auto alice = std::move(aliceConnect).value();

  ua::client::ConnectionConfig anonymousConfig;
  anonymousConfig.endpointUrl = server.endpoint_url();
  anonymousConfig.securityMode = MessageSecurityMode::SignAndEncrypt;
  anonymousConfig.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  anonymousConfig.serverCertificate = mServerParty.cert;
  auto anonymousConnect = mClient->try_connect_sync(std::move(anonymousConfig));
  ASSERT_TRUE(anonymousConnect.is_good()) << to_string(anonymousConnect.status_code());
  auto anonymous = std::move(anonymousConnect).value();

  // Part 12 7.8.3.3 / REQ-CGF-3: the group exists only to carry its TrustList, so it declares no
  // certificate types. Read before the mutation, while the session is certainly alive.
  {
    auto certificateTypes = alice.try_read_value_sync(
      NodeId{VariableId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateTypes});
    ASSERT_TRUE(certificateTypes.is_good())
      << "the DefaultUserTokenGroup must be published for its CertificateTypes to be readable: "
      << to_string(certificateTypes.status_code());
    EXPECT_TRUE(certificateTypes.value().value().as<Array<NodeId>>().empty())
      << "Part 12 7.8.3.3: this group shall leave the CertificateTypes list empty";
  }

  const auto thumbprint = fmt::format("{:02X}", fmt::join(mUserAlice.cert->thumbprint(), ""));
  std::vector<Variant> removeArgs;
  removeArgs.emplace_back(String{thumbprint});
  removeArgs.emplace_back(true);

  auto removed = alice.typed().try_call_method_sync(
    NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList},
    NodeId{MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_RemoveCertificate},
    std::move(removeArgs));
  ASSERT_TRUE(removed.is_good()) << "RemoveCertificate on the user-token TrustList must be wired: "
                                 << to_string(removed.status_code());
  ASSERT_TRUE(removed.value().is_good()) << to_string(removed.value().status_code());
  // RATIFIED (owner report 2026-10-03, BR-13): RemoveCertificate changes the TrustList at once (OPC 10000-12
  // 7.8.2.5, no transaction), so the re-evaluation follows its response; the ApplyChanges this test then sent
  // found Alice's Session already closed.

  // The close is deferred past the Method response by design, so poll rather than read once.
  const auto aliceStillUsable = [&]
  {
    return alice.try_read_value_sync(NodeId{VariableId::Server_ServerStatus_State}).is_good();
  };
  bool aliceClosed = false;
  for (int attempt = 0; attempt < 100 && !aliceClosed; ++attempt)
  {
    aliceClosed = !aliceStillUsable();
    if (!aliceClosed)
      std::this_thread::sleep_for(50ms);
  }
  EXPECT_TRUE(aliceClosed)
    << "Part 12 7.10.6: once its certificate left the trust list Alice's session must be closed";

  auto anonymousRead = anonymous.try_read_value_sync(NodeId{VariableId::Server_ServerStatus_State});
  EXPECT_TRUE(anonymousRead.is_good())
    << "a session with no X.509 identity was not invalidated by the change and must survive it: "
    << to_string(anonymousRead.status_code());

  (void)anonymous.try_close_sync();
  (void)alice.try_close_sync();
}

// Consumer: Part 12 section 7.10.3 (ServerConfigurationType, Table 64) and section 7.8.3.3.
//
// CertificateGroups is what a client browses to learn which certificates it may push.
// DefaultApplicationGroup is mandatory; DefaultHttpsGroup and DefaultUserTokenGroup are optional and must
// be ABSENT where the server does not implement them. A group that is published but backed by nothing
// advertises a capability the server does not have, and a client that pushed a trust list into it would be
// misled without ever seeing an error.
//
// A plausible implementation gets this wrong by importing the standard NS0 nodeset verbatim: that file
// carries all three groups as unconditional components of the CertificateGroups folder, so every optional
// group is published whether or not anything is wired behind it. The two servers below differ only in
// whether a user-token trust list is configured - which is exactly what decides whether the SDK builds a
// user-token TrustListManager - so the group's presence must track that field. Neither server implements
// an HTTPS transport, and there is no HTTPS trust-list configuration at all, so DefaultHttpsGroup must
// never appear on either.
//
// @verifies AC-SVR-PULLCRT-003-CERTIFICATE-GROUPS
// @relation(SVR-PULLCRT-003, scope=function)
//
// KNOWN RED: the behaviour is UNIMPLEMENTED and this test is correct as written - do not weaken it.
// SVR-PULLCRT-003 states that the SDK ships DefaultApplicationGroup always and DefaultUserTokenGroup
// only where a user-token trust list is configured, the HTTPS group being a planned extension; the
// criterion adds that an unimplemented optional group is ABSENT rather than empty. The server does
// the opposite: `ServerImpl::create_standard_nodes_from_nodeset` imports the whole NS0 Server subtree
// verbatim (sdk/implementation/server/ua_server_impl.cpp:3452,
// `import_node_and_forward_refs_async(NodeId{ObjectId::Server}, ...)`), which materialises all three
// CertificateGroups children with their TrustList and CertificateTypes subtrees, and nothing prunes
// the unbacked ones afterwards - `wire_push_management` only conditionally WIRES handlers
// (sdk/implementation/server/security/ua_push_management_wiring.cpp:1571). Every conjunct fails on the
// live build: DefaultHttpsGroup is browsable on both servers with a readable CertificateTypes, and
// DefaultUserTokenGroup is browsable with a readable CertificateTypes even with no user-token store.
// It goes green once the group set is derived from the configuration rather than from the nodeset.
TEST_F(ConfigurationUserTokenTrust, CertificateGroupsPublishOnlyTheGroupsTheServerImplements)
{
  // Every BrowseName reachable from the CertificateGroups folder. Read off a real Browse, because the
  // obligation is about what a CLIENT can discover, not about which NodeIds happen to resolve.
  const auto groupBrowseNames = [](auto& connection)
  {
    std::vector<QualifiedName> names;
    auto cursor = connection.typed().browse(NodeId{ObjectId::ServerConfiguration_CertificateGroups});
    for (int guard = 0; guard < 256; ++guard)
    {
      auto entry = cursor.try_next_sync();
      if (entry.is_bad())
        break;
      names.push_back(entry.value().browseName);
    }
    return names;
  };

  const auto contains = [](const std::vector<QualifiedName>& names, std::string_view group)
  {
    return std::any_of(
      names.begin(), names.end(), [&](const QualifiedName& name) { return name == QualifiedName{0, group}; });
  };

  // A missing group and a group hidden by permissions look identical to `contains`, so every failure below
  // prints what the Browse actually returned.
  const auto listed = [](const std::vector<QualifiedName>& names)
  {
    std::string out;
    for (const auto& name : names)
    {
      out += out.empty() ? "" : ", ";
      out += std::to_string(name.namespace_index()) + ":" + std::string{name.name()};
    }
    return out.empty() ? std::string{"<nothing>"} : out;
  };

  // "Absent rather than empty" is only settled by the subtree: a group whose CertificateTypes Property
  // still reads is present-and-inert, which is the failure this criterion names.
  // Reports WHY as well as whether: an absent node (Bad_NodeIdUnknown) and a node hidden by permissions
  // (Bad_UserAccessDenied) both make an absence assertion pass, and only one of them is this criterion.
  const auto certificateTypesStatus = [](auto& connection, VariableId property)
  {
    auto read = connection.try_read_value_sync(NodeId{property});
    if (read.is_bad())
      return read.status_code();
    return read.value().status().value_or(ua::StatusCode{ua::Status::Good});
  };
  const auto certificateTypesReadable = [&certificateTypesStatus](auto& connection, VariableId property)
  {
    return certificateTypesStatus(connection, property).is_good();
  };

  // The server that DOES implement the optional user-token group.
  const auto userPath = seed_user_store("groups_user_store", {mUserAlice.cert});
  UserTokenServer implemented{mCrypto, base_config(userPath)};
  ASSERT_FALSE(implemented.endpoint_url().empty());

  auto implementedConnect = connect_as_security_admin(implemented.endpoint_url());
  ASSERT_TRUE(implementedConnect.is_good()) << to_string(implementedConnect.status_code());
  auto implementedSession = std::move(implementedConnect).value();

  const auto implementedNames = groupBrowseNames(implementedSession);
  ASSERT_FALSE(implementedNames.empty())
    << "the CertificateGroups folder must browse to something, or every absence asserted below is vacuous";
  EXPECT_TRUE(contains(implementedNames, "DefaultApplicationGroup"))
    << "Part 12 7.10.3: DefaultApplicationGroup is the one group every Server shall support; the Browse "
       "returned: "
    << listed(implementedNames);
  EXPECT_TRUE(contains(implementedNames, "DefaultUserTokenGroup"))
    << "a user-token trust list is configured, so the optional group that carries it must be published";
  EXPECT_FALSE(contains(implementedNames, "DefaultHttpsGroup"))
    << "no HTTPS transport and no HTTPS trust-list configuration exists, so this optional group must be "
       "absent rather than published inert";

  EXPECT_TRUE(certificateTypesReadable(implementedSession,
    VariableId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateTypes))
    << "an implemented group's subtree must be reachable; this is the control that makes an UNREADABLE "
       "CertificateTypes below mean absent rather than merely unreadable. Read returned "
    << to_string(certificateTypesStatus(implementedSession,
         VariableId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateTypes));
  EXPECT_FALSE(certificateTypesReadable(
    implementedSession, VariableId::ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateTypes))
    << "an unimplemented group must leave no readable subtree behind either";

  (void)implementedSession.try_close_sync();

  // The same server with the one field that backs the optional group removed.
  UserTokenServer unimplemented{mCrypto, base_config(std::nullopt)};
  ASSERT_FALSE(unimplemented.endpoint_url().empty());

  auto unimplementedConnect = connect_as_security_admin(unimplemented.endpoint_url());
  ASSERT_TRUE(unimplementedConnect.is_good()) << to_string(unimplementedConnect.status_code());
  auto unimplementedSession = std::move(unimplementedConnect).value();

  const auto unimplementedNames = groupBrowseNames(unimplementedSession);
  ASSERT_FALSE(unimplementedNames.empty())
    << "the CertificateGroups folder must still browse to something without a user-token store";
  EXPECT_TRUE(contains(unimplementedNames, "DefaultApplicationGroup"))
    << "the mandatory group is not affected by the user-token configuration";
  EXPECT_FALSE(contains(unimplementedNames, "DefaultUserTokenGroup"))
    << "with no user-token trust list the server implements no user-token group, so it must be absent; "
       "the server above shows the same Browse yields it once the group IS backed";
  EXPECT_FALSE(contains(unimplementedNames, "DefaultHttpsGroup"))
    << "the HTTPS group is unimplemented here too";
  EXPECT_TRUE(certificateTypesReadable(unimplementedSession,
    VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateTypes))
    << "the positive control on THIS session: the mandatory group's CertificateTypes reads, so an "
       "unreadable one below means the optional group is absent and not that this session reads nothing";
  EXPECT_FALSE(certificateTypesReadable(unimplementedSession,
    VariableId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateTypes))
    << "absent, not present-and-empty: an unbacked group must leave no readable subtree";

  (void)unimplementedSession.try_close_sync();
}

// Part 12 section 7.10.3 (ServerConfigurationType, Table 64) and section 7.8.3.3.
//
// "Absent rather than empty" is a claim about the whole group, not just about the child list the
// CertificateGroups folder browses to. A CertificateGroup exists to carry a TrustList Object, and that
// Object is what a client pushes into; so a group the Server does not implement must leave no TrustList
// behind it either.
//
// A plausible implementation gets this wrong in the way that is hardest to see: it hides the group node
// the folder browses to while the NS0 import has already materialised the TrustList and its Open /
// AddCertificate Methods underneath their own well-known NodeIds. A client that never browsed - the
// normal case, since those ids are fixed in the standard nodeset - would then push a trust list into a
// group nothing is wired behind and be answered as though the push had landed.
// @verifies AC-SVR-PULLCRT-003-CERTIFICATE-GROUPS
// @relation(SVR-PULLCRT-003, scope=function)
TEST_F(ConfigurationUserTokenTrust, UnimplementedCertificateGroupsLeaveNoTrustListSubtree)
{
  // The components of @p node, read off a real Browse - the same oracle a client has.
  const auto components = [](auto& connection, const NodeId& node)
  {
    std::vector<QualifiedName> names;
    auto cursor = connection.typed().browse(node);
    for (int guard = 0; guard < 256; ++guard)
    {
      auto entry = cursor.try_next_sync();
      if (entry.is_bad())
        break;
      names.push_back(entry.value().browseName);
    }
    return names;
  };

  // No user-token trust list, so this server implements neither optional group.
  UserTokenServer server{mCrypto, base_config(std::nullopt)};
  ASSERT_FALSE(server.endpoint_url().empty());

  auto connect = connect_as_security_admin(server.endpoint_url());
  ASSERT_TRUE(connect.is_good()) << to_string(connect.status_code());
  auto session = std::move(connect).value();

  // The control, on THIS session: the mandatory group's TrustList browses to its Methods and
  // Properties. Without it an empty Browse below would say only that this session browses nothing.
  const auto applicationTrustList = components(
    session, NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList});
  ASSERT_FALSE(applicationTrustList.empty())
    << "DefaultApplicationGroup is the one group every Server shall support, so its TrustList must be "
       "reachable - otherwise every absence asserted below is vacuous";

  const auto httpsTrustList =
    components(session, NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList});
  EXPECT_TRUE(httpsTrustList.empty())
    << "no HTTPS transport and no HTTPS trust-list configuration exists, so the group is absent and must "
       "leave no TrustList for a client to push into";

  const auto userTokenTrustList = components(
    session, NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList});
  EXPECT_TRUE(userTokenTrustList.empty())
    << "with no user-token trust list configured the user-token group is unimplemented, so its TrustList "
       "must be gone with it; the DefaultApplicationGroup TrustList above shows the same Browse does find "
       "one where the group IS implemented";

  (void)session.try_close_sync();
}

}  // namespace

// OPC 10000-4 7.41.4 Table 193 and OPC 10000-6 6.8.3 (owner decision 2026-10-03, BR-15): a None-channel
// endpoint whose user tokens are secured presents ONE certificate, which shall be valid for every token
// policy. With only a 4096-bit RSA certificate held, an endpoint offering Basic128Rsa15 (RSA 1024-2048 bits)
// beside Basic256Sha256 cannot be served, so the server refuses to start with Bad_ConfigurationError naming
// the endpoint. Control: offering Basic256Sha256 alone, the same server starts.
// @relation(AC-SVR-IDENT-008-A-NONE-ENDPOINT-CERTIFICATE-IS-VALID-FOR-EVERY-TOKEN-POLICY, scope=function)
TEST_F(ConfigurationTrust, ANoneEndpointWhoseTokenPoliciesShareNoCertificateIsRefusedAtStart)
{
  Crypto::SubjectAlternateName san;
  san.uris.push_back(std::string{serverUri});
  san.hostnames = {"localhost", "127.0.0.1"};
  auto identity = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Token policy server"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    san,
    CertificateType::RsaSha256Application,
    4096);
  ASSERT_TRUE(identity.is_good());
  auto [keys, certificate] = std::move(identity).value();

  const auto startWith = [&](std::vector<SecurityPolicyId> tokenPolicies, const std::string& directory)
  {
    const auto storePath = mPkiRoot / directory;
    std::filesystem::create_directories(storePath);
    auto store = CertificateStoreFiles::create(mClientPool.executor(), mCrypto, {.trustListPath = storePath});
    CertificateStore::ApplicationCertificate own;
    own.certificateType = CertificateType::RsaSha256Application;
    own.certificate = certificate;
    own.keys = keys;
    store->add_to_application_certificates_sync(own);

    auto application = ua::test_utils::create_test_config();
    application.application_description_part().applicationUri = std::string{serverUri};
    application.file_trust_list_configuration().defaultApplicationGroupTrustListPath = storePath;
    application.allowInsecureEndpoints = true;
    application.allowDeprecatedSecurityPolicies = true;
    ServerComponents components{.crypto = mCrypto, .logSink = test_log_sink(), .logLevel = LogLevel::Debug};
    components.authenticator = std::make_shared<AnonymousAuthenticator>();
    boost::asio::thread_pool pool{2};
    auto server = Server::create(pool.executor(),
      server::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = std::move(application)},
      std::move(components));
    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    const auto listener = server.listen_sync(std::move(bind), {});
    ServerEndpointConfig endpoint;
    endpoint.name = "None_SecuredTokens";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    for (const auto policy : tokenPolicies)
      endpoint.userIdentityTokens.push_back(create_user_token_policy(UserTokenType::UserName, policy));
    server.add_endpoint(listener, std::move(endpoint));
    auto started = server.try_start_sync();
    (void)server.try_shutdown_sync({.grace = std::chrono::seconds{0}});
    ::ua::test_utils::stop_pool_in_teardown(pool, "token-policy-server");
    return started;
  };

  const auto refused =
    startWith({SecurityPolicyId::Basic128Rsa15, SecurityPolicyId::Basic256Sha256}, "token_policies_mixed");
  ASSERT_TRUE(refused.is_bad()) << "no held certificate is valid for both token policies";
  EXPECT_EQ(refused.status_code().as_status(), Status::BadConfigurationError);
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_NE(ua::to_string(*refused.shared_detail()).find("None_SecuredTokens"), std::string::npos)
    << ua::to_string(*refused.shared_detail());

  const auto accepted = startWith({SecurityPolicyId::Basic256Sha256}, "token_policies_modern");
  EXPECT_TRUE(accepted.is_good()) << "control: the 4096-bit certificate serves Basic256Sha256: "
                                  << to_string(accepted.status_code());
}
