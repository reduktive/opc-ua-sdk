// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The identity a monitored Variable's value read handler sees in its sampling reads (NR-49, NR-70 A3): the
// user of the Session that monitors it, and after an ActivateSession with another user, that user from the
// next tick. A real server with UserName users; the client activates its Session over a SignAndEncrypt
// channel.

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "subscription.h"
#include "test_components.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_built_in_authenticators.h"
#include "ua_certificate_store_files.h"
#include "ua_core_client.h"
#include "ua_crypto.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_instance_utils.h"
#include "ua_node_accessor.h"
#include "ua_numeric_range_parser.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_security_policy.h"
#include "ua_server.h"
#include "ua_server_configuration.h"
#include "ua_to_string.h"
#include "ua_user_identity.h"
#include "ua_user_token_policy.h"
#include "ua_value_source.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

struct KeyMaterial
{
  std::shared_ptr<const AsymmetricKeyPair> keys;
  std::shared_ptr<const X509Certificate> cert;
};

KeyMaterial create_self_signed_cert(
  const std::shared_ptr<const Crypto>& crypto, const std::string& commonName, const std::string& uri)
{
  Crypto::Name subject;
  subject.commonName = commonName;
  UtcTime expiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName altName;
  altName.uris.push_back(uri);
  altName.hostnames.push_back("localhost");
  altName.hostnames.push_back("127.0.0.1");

  auto result = crypto->try_create_self_signed_application_instance_certificate_sync(
    subject, expiry, altName, CertificateType::RsaSha256Application, 2048);
  if (result.is_bad())
    throw std::runtime_error("Failed to create certificate: " + commonName);

  auto [keys, cert] = std::move(result).value();
  return {std::move(keys), std::move(cert)};
}

/// One read of the monitored Variable's Value: whether it named an identity, and that identity's user.
struct RecordedRead
{
  bool hasIdentity{false};
  std::string userId;
};

/// The reads the Variable's value read handler answered, in order.
class ReadLog
{
public:
  void record(const AccessIdentity* identity)
  {
    RecordedRead read;
    if (identity)
    {
      read.hasIdentity = true;
      read.userId = identity->user().userId;
    }
    const std::lock_guard lock{mMutex};
    mReads.push_back(std::move(read));
  }

  std::vector<RecordedRead> reads() const
  {
    const std::lock_guard lock{mMutex};
    return mReads;
  }

  void clear()
  {
    const std::lock_guard lock{mMutex};
    mReads.clear();
  }

private:
  mutable std::mutex mMutex;
  std::vector<RecordedRead> mReads;
};

bool wait_for_condition(const std::function<bool()>& condition, std::chrono::milliseconds timeout)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!condition())
  {
    if (std::chrono::steady_clock::now() > deadline)
      return false;
    std::this_thread::sleep_for(10ms);
  }
  return true;
}

std::string describe_reads(const std::vector<RecordedRead>& reads)
{
  std::string out;
  for (const auto& read : reads)
  {
    out += (out.empty() ? "" : ", ") + (read.hasIdentity ? read.userId : std::string{"<null>"});
  }
  return "[" + out + "]";
}

}  // namespace

class SampledCaller : public ::testing::Test
{
protected:
  static constexpr const char* sClientUri = "urn:test:sampled-caller:client";
  static constexpr const char* sUserPolicyId = "user-rsa";
  static constexpr const char* sAliceUser = "alice";
  static constexpr const char* sAlicePassword = "alice-pw";
  static constexpr const char* sBobUser = "bob";
  static constexpr const char* sBobPassword = "bob-pw";

  static void SetUpTestSuite()
  {
    sLogSink = test_log_sink();
    sCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });
    sServerCert = create_self_signed_cert(sCrypto, "SampledCallerServer", "urn:test:sampled-caller:server");
    sClientCert = create_self_signed_cert(sCrypto, "SampledCallerClient", sClientUri);

    sServerThreadPool = std::make_unique<boost::asio::thread_pool>();
    auto serverExecutor = sServerThreadPool->executor();

    sTempDir = std::filesystem::temp_directory_path() /
               ("ua_sampled_caller_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(sTempDir);

    auto appStorePath = sTempDir / "app_group";
    std::filesystem::create_directories(appStorePath);
    TrustListValidationOptions validationOptions;
    sAppCertStore = CertificateStoreFiles::create(
      serverExecutor, sCrypto, {.trustListPath = appStorePath, .validationOptions = validationOptions});
    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = sServerCert.cert;
      appCert.keys = sServerCert.keys;
      sAppCertStore->add_to_application_certificates_sync(appCert);
    }
    sAppCertStore->add_to_trusted_certificates_sync(sClientCert.cert);

    // Two UserName users, both AuthenticatedUser, which the test namespace grants to read its Variable.
    ServerComponents components{.crypto = sCrypto,
      .applicationGroupCertificateStore = sAppCertStore,
      .logSink = sLogSink,
      .logLevel = LogLevel::Debug};
    auto composite = std::make_shared<CompositeAuthenticator>();
    composite->add(UserTokenKind::UserName,
      std::make_shared<SimpleUserPasswordAuthenticator>(
        [](std::string_view username, const ua::SecureString& password)
        {
          const std::string_view secret{password.c_str()};
          return (username == sAliceUser && secret == sAlicePassword) ||
                 (username == sBobUser && secret == sBobPassword);
        }));
    components.authenticator = std::move(composite);
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::AuthenticatedUser}});

    auto appCfg = ua::test_utils::create_test_config();
    ServerConfig serverCfg;
    serverCfg.connectionThrottling.enabled = false;
    server::CreateConfig serverCreateCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};
    sServer.emplace(Server::create(serverExecutor, std::move(serverCreateCfg), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    sListenerHandle = sServer->listen_sync(std::move(bind), {});
    {
      ServerEndpointConfig endpoint;
      endpoint.name = "B256S256_SaE_SampledCaller";
      endpoint.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
      endpoint.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      UserTokenPolicy userPolicy;
      userPolicy.policy_id() = std::string{sUserPolicyId};
      userPolicy.token_type() = UserTokenType::UserName;
      userPolicy.security_policy_uri() =
        std::string{SecurityPolicy::create(SecurityPolicyId::Basic256Sha256)->uri()};
      endpoint.userIdentityTokens.push_back(std::move(userPolicy));
      sServer->add_endpoint(sListenerHandle, endpoint);
    }

    auto addressSpace = sServer->address_space();
    auto testNamespace = default_ns::Namespace::create("urn:test:sampled-caller", serverExecutor);
    const auto namespaceIndex = addressSpace.add_namespace_sync(testNamespace);
    ua::test_helpers::grant_namespace_to_test_client(addressSpace, namespaceIndex);

    sVariableId = NodeId{namespaceIndex, uint32_t{1000}};
    auto node = addressSpace.create_node_sync(sVariableId, NodeClass::Variable);
    auto variable = node.as<VariableAccessor>();
    variable->set_browse_name(QualifiedName{namespaceIndex, "SampledInt32"});
    variable->set_display_name(LocalizedText{"", "SampledInt32"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{42});
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, sVariableId);

    sReads = std::make_shared<ReadLog>();
    {
      std::promise<VoidResult> installed;
      auto installedFuture = installed.get_future();
      ua::instance_utils::resolve_and_set_value_source_async(addressSpace,
        sVariableId,
        ua::make_value_source(
          [reads = sReads](const ValueSource::ReadContext& context,
            const Node& /*node*/,
            const ReadValueId& read,
            std::function<void(DataValueResult)>
              done)
          {
            reads->record(context.caller != nullptr ? context.caller->identity.get() : nullptr);
            DataValue value{Variant{int32_t{42}}};
            ua::index_range_utils::apply_to_value(value, read.index_range());
            done(DataValueResult{std::move(value)});
          }),
        [&installed](VoidResult result) { installed.set_value(std::move(result)); });
      const auto result = installedFuture.get();
      ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
    }

    sServer->start_sync();
    sEndpointUrl = sServer->advertised_urls(sListenerHandle).front().str();

    sClientThreadPool = std::make_unique<boost::asio::thread_pool>();
    auto clientStorePath = sTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);
    sClientCertStore = CertificateStoreFiles::create(sClientThreadPool->executor(),
      sCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});
    {
      CertificateStore::ApplicationCertificate cert;
      cert.certificateType = CertificateType::RsaSha256Application;
      cert.certificate = sClientCert.cert;
      cert.keys = sClientCert.keys;
      sClientCertStore->add_to_application_certificates_sync(cert);
    }
    sClientCertStore->add_to_trusted_certificates_sync(sServerCert.cert);

    auto clientConfig = ua::test_utils::create_test_config();
    clientConfig.application_description_part().applicationUri = sClientUri;
    sClient.emplace(CoreClient::create(sClientThreadPool->executor(),
      client::CreateConfig{
        .identity = ApplicationIdentity::load_default(), .application = std::move(clientConfig)},
      ua::client::ClientComponents{.crypto = sCrypto,
        .applicationGroupCertificateStore = sClientCertStore,
        .logSink = sLogSink,
        .logLevel = LogLevel::Debug}));
  }

  static void TearDownTestSuite()
  {
    sClient.reset();
    if (sServer)
      (void)sServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    sServer.reset();
    sAppCertStore.reset();
    sClientCertStore.reset();
    if (sServerThreadPool)
      sServerThreadPool->join();
    if (sClientThreadPool)
      sClientThreadPool->join();
    sServerThreadPool.reset();
    sClientThreadPool.reset();
    sReads.reset();
    sCrypto.reset();
    sLogSink.reset();
    if (!sTempDir.empty())
      std::filesystem::remove_all(sTempDir);
  }

  void SetUp() override
  {
    ASSERT_TRUE(sServer.has_value()) << "the suite's server did not start";
    sReads->clear();
  }

  static SecureChannel open_secure_channel()
  {
    return sClient->open_channel_sync({.endpointUrl = sEndpointUrl,
      .securityMode = MessageSecurityMode::SignAndEncrypt,
      .securityPolicyId = SecurityPolicyId::Basic256Sha256,
      .serverCertificate = sServerCert.cert});
  }

  static ua::client::Session::ActivateConfig user_identity(const char* username, const char* password)
  {
    ua::client::Session::ActivateConfig config;
    config.policyId = std::string{sUserPolicyId};
    config.identity =
      UsernamePasswordIdentity{.username = std::string{username}, .password = std::string{password}};
    return config;
  }

  /// A Subscription and one monitored item on the Variable's Value, sampled every 100 ms. No Publish is sent;
  /// the lifetime outlasts the test.
  static SubscriptionWithMonitoredItem monitor_the_variable(ua::client::Session& session)
  {
    return create_subscription_with_monitored_item(session,
      sVariableId,
      SubscriptionOptions{.publishingInterval = 100.0, .lifetimeCount = 3000, .keepAliveCount = 10},
      MonitoringOptions{.samplingInterval = 100.0});
  }

  static inline std::shared_ptr<LogSink> sLogSink;
  static inline std::shared_ptr<const Crypto> sCrypto;
  static inline KeyMaterial sServerCert;
  static inline KeyMaterial sClientCert;
  static inline std::unique_ptr<boost::asio::thread_pool> sServerThreadPool;
  static inline std::unique_ptr<boost::asio::thread_pool> sClientThreadPool;
  static inline std::filesystem::path sTempDir;
  static inline std::shared_ptr<CertificateStore> sAppCertStore;
  static inline std::shared_ptr<CertificateStore> sClientCertStore;
  static inline std::optional<Server> sServer;
  static inline ListenerHandle sListenerHandle{0};
  static inline std::string sEndpointUrl;
  static inline NodeId sVariableId;
  static inline std::shared_ptr<ReadLog> sReads;
  static inline std::optional<CoreClient> sClient;
};

// The first read after the item is created may be the Subscription's read of the initial value; every read
// after it is a sampling read, and each must name alice.
// @relation(AC-COMP-ADDRSP-SAMPLED-CALLER-02-A-VALUE-HANDLER-SEES-THE-SESSIONS-IDENTITY, scope=function)
TEST_F(SampledCaller, AValueHandlerSeesTheSessionsIdentity)
{
  auto channel = open_secure_channel();
  auto session = channel.create_session_sync({.sessionName = "SampledCallerAlice"});
  session.activate_sync(user_identity(sAliceUser, sAlicePassword));
  const auto monitored = monitor_the_variable(session);
  ASSERT_NE(monitored.monitoredItemId, 0u);

  ASSERT_TRUE(wait_for_condition([] { return sReads->reads().size() >= 3u; }, 10s))
    << "no sampling read followed the initial value: " << describe_reads(sReads->reads());
  const auto reads = sReads->reads();
  for (std::size_t i = 1; i < reads.size(); ++i)
  {
    EXPECT_TRUE(reads[i].hasIdentity && reads[i].userId == sAliceUser)
      << "sampling read " << i << " did not name alice: " << describe_reads(reads);
  }

  delete_subscription(session, monitored.subscriptionId);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// The same Session is activated again as bob. Before that the sampling reads name alice; after it answers
// Good a sampling read names bob, and no read after that one names alice.
// @relation(AC-COMP-ADDRSP-SAMPLED-CALLER-02-AFTER-ACTIVATE-SESSION-WITH-A-NEW-USER-THE-NEXT-SAMPLE-USES-IT, scope=function)
TEST_F(SampledCaller, AfterActivateSessionWithANewUserTheNextSampleUsesIt)
{
  auto channel = open_secure_channel();
  auto session = channel.create_session_sync({.sessionName = "SampledCallerAliceThenBob"});
  session.activate_sync(user_identity(sAliceUser, sAlicePassword));
  const auto monitored = monitor_the_variable(session);
  ASSERT_NE(monitored.monitoredItemId, 0u);

  ASSERT_TRUE(wait_for_condition([] { return sReads->reads().size() >= 3u; }, 10s))
    << "no sampling read followed the initial value: " << describe_reads(sReads->reads());
  const auto beforeCount = sReads->reads().size();

  const auto activated = session.try_activate_sync(user_identity(sBobUser, sBobPassword));
  ASSERT_TRUE(activated.is_good()) << "the ActivateSession as bob failed: "
                                   << to_string(activated.status_code());
  const auto afterCount = sReads->reads().size();

  const auto firstBobFrom = [](const std::vector<RecordedRead>& reads, std::size_t from)
  {
    return std::find_if(reads.begin() + static_cast<std::ptrdiff_t>(std::min(from, reads.size())),
      reads.end(),
      [](const RecordedRead& read) { return read.hasIdentity && read.userId == sBobUser; });
  };
  ASSERT_TRUE(wait_for_condition(
    [&]
    {
      const auto reads = sReads->reads();
      const auto firstBob = firstBobFrom(reads, afterCount);
      return firstBob != reads.end() && reads.end() - firstBob >= 3;
    },
    10s))
    << "after the ActivateSession as bob no sampling read named bob and was followed by two more: "
    << describe_reads(sReads->reads());

  const auto reads = sReads->reads();
  for (std::size_t i = 1; i < beforeCount; ++i)
  {
    EXPECT_TRUE(reads[i].hasIdentity && reads[i].userId == sAliceUser)
      << "sampling read " << i
      << ", before the ActivateSession as bob, did not name alice: " << describe_reads(reads);
  }
  const auto firstBob = static_cast<std::size_t>(firstBobFrom(reads, afterCount) - reads.begin());
  for (std::size_t i = firstBob + 1; i < reads.size(); ++i)
  {
    EXPECT_FALSE(reads[i].hasIdentity && reads[i].userId == sAliceUser)
      << "read " << i << ", after the first read naming bob, named alice: " << describe_reads(reads);
  }

  delete_subscription(session, monitored.subscriptionId);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}
