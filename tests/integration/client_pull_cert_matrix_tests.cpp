// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Integration tests for the client Pull-Certificate-Management GDS transport (Part 12 section 7 pull
/// model),
///        driven against the in-tree reference server. This slice covers the GDS bootstrap CONNECT
///        (CL-PULLCRT-001 / CL-PULLCRT-002): `PullCertificateManagerClientHost::open_gds_connection_async`
///        opens a real SignAndEncrypt + Anonymous channel to the server, validated against the bootstrap
///        trust store - the prerequisite the TrustList / cert-request RPCs ride. The trust-list download
///        (CL-PULLCRT-005) and the revalidation broadcast (CL-PULLCRT-006) land in later slices; the
///        cert-signing half (CL-PULLCRT-003/004) is deferred pending a GDS CertificateManager oracle.

#include "compliance_helpers.h"
#include "gds_emulator.h"

#include "ua_core_client_impl.h"
#include "ua_client_observers.h"
#include "ua_client_subscription.h"
#include "ua_client_test_hooks.h"  // CoreClientTestAccess::impl
#include "ua_connection_config.h"
#include "ua_connection.h"
#include "ua_crypto_types.h"  // SecurityPolicyId
#include "ua_message_security_mode.h"
#include "ua_date_time.h"
#include "ua_node_class.h"
#include "ua_object_id.h"
#include "ua_pull_certificate_manager_client_host.h"
#include "ua_pull_certificate_manager_host.h"  // GdsConnectionRequest
#include "ua_pull_certificate_manager_test_access.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_trust_list_data_type.h"

#include <gtest/gtest.h>

#include <chrono>
#include <atomic>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

namespace
{
using ua::client::CoreClientTestAccess;
using ua::client::detail::PullCertificateManagerClientHost;
using PullAccess = ua::client::detail::PullCertificateManagerTestAccess;
using Host = ua::client::detail::PullCertificateManagerHost;
using namespace std::chrono_literals;

class PullLifecycleObserver final : public ua::client::SecurityObserver
{
public:
  void on_pull_cert_management_lifecycle(const ua::client::Connection*,
    ua::client::PullCertLifecycleEvent event, std::shared_ptr<const ua::ErrorDetail>) override
  {
    if (event == ua::client::PullCertLifecycleEvent::TrustListCommitted)
    {
      trustListCommitted.fetch_add(1);
    }
    if (event == ua::client::PullCertLifecycleEvent::RevalidationCompleted)
    {
      revalidationCompleted.fetch_add(1);
    }
  }

  std::atomic<int> trustListCommitted{0};
  std::atomic<int> revalidationCompleted{0};
};

class CertificateReconnectObserver final : public ua::client::ConnectionObserver
{
public:
  void on_reconnecting(const ua::client::Connection&, std::size_t, ua::client::ReconnectCause cause) override
  {
    if (std::holds_alternative<ua::client::CertRotated>(cause))
      certRotatedAttempts.fetch_add(1);
  }

  void on_reconnected(const ua::client::Connection&, ua::client::ReconnectOutcome reconnectOutcome) override
  {
    {
      const std::lock_guard lock(mutex);
      outcome = std::move(reconnectOutcome);
    }
    reconnected.store(true);
  }

  std::atomic<int> certRotatedAttempts{0};
  std::atomic<bool> reconnected{false};
  std::mutex mutex;
  std::optional<ua::client::ReconnectOutcome> outcome;
};

/// Builds a client-host over the fixture's real (secured-store) Client, so its open_gds drives the actual
/// `Client::connect_async` to the reference server.
class ClientPullCertGds : public ComplianceSecured
{
protected:
  void SetUp() override
  {
    ComplianceSecured::SetUp();
    auto addressSpace = mServer->address_space();
    mGdsNamespace =
      default_ns::Namespace::create("http://opcfoundation.org/UA/GDS/", mServerThreadPool.executor());
    mGdsNamespaceIndex = addressSpace.add_namespace_sync(mGdsNamespace);
    // ComplianceSecured builds its own server and does not run ComplianceBase's namespace grant, so
    // this namespace declares nothing, publishes an ENGAGED, EMPTY default and refuses every node it
    // owns - the Directory Object and the GDS Methods below included. A client then cannot resolve
    // them: the browse path translate answers BadNoMatch, which reads as "this server publishes no
    // GDS", and a Method that cannot be found is never called.
    grant_namespace_to_test_client(addressSpace, mGdsNamespaceIndex);

    mDirectoryId = ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7000}};
    auto directoryNode = addressSpace.create_node_sync(mDirectoryId, ua::NodeClass::Object);
    auto directory = directoryNode.as<ua::ObjectAccessor>();
    ASSERT_TRUE(directory);
    directory->set_browse_name(ua::QualifiedName{mGdsNamespaceIndex, "Directory"});
    directory->set_display_name(ua::LocalizedText{"", "Directory"});
    auto objectsFolder = addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, mDirectoryId);

    mStartMethodId = ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7001}};
    auto startNode = addressSpace.create_node_sync(mStartMethodId, ua::NodeClass::Method);
    auto startMethod = startNode.as<ua::MethodAccessor>();
    ASSERT_TRUE(startMethod);
    startMethod->set_browse_name(ua::QualifiedName{mGdsNamespaceIndex, "StartNewKeyPairRequest"});
    startMethod->set_display_name(ua::LocalizedText{"", "StartNewKeyPairRequest"});
    startMethod->set_executable(true);
    directoryNode.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, mStartMethodId);
    auto* startSource = mGdsNamespace->find_node<Node>(mStartMethodId)->method_call_source();
    ASSERT_NE(startSource, nullptr);
    startSource->set_call_handler(
      [this](const ua::CallMethodRequest& request,
        std::shared_ptr<const ua::MethodCallContext>
          context,
        std::function<void(ua::CallResult)>
          callback)
      {
        {
          const std::lock_guard lock(mMethodMutex);
          mStartArguments.assign(request.input_arguments().begin(), request.input_arguments().end());
          mStartSessionId = context ? context->sessionId : ua::NodeId{};
        }
        ++mStartCalls;
        ua::CallMethodResult result;
        result.output_arguments().push_back(ua::Variant{ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7100}}});
        callback(ua::CallResult{std::move(result)});
      });

    mFinishMethodId = ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7002}};
    auto finishNode = addressSpace.create_node_sync(mFinishMethodId, ua::NodeClass::Method);
    auto finishMethod = finishNode.as<ua::MethodAccessor>();
    ASSERT_TRUE(finishMethod);
    finishMethod->set_browse_name(ua::QualifiedName{mGdsNamespaceIndex, "FinishRequest"});
    finishMethod->set_display_name(ua::LocalizedText{"", "FinishRequest"});
    finishMethod->set_executable(true);
    directoryNode.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, mFinishMethodId);
    auto* finishSource = mGdsNamespace->find_node<Node>(mFinishMethodId)->method_call_source();
    ASSERT_NE(finishSource, nullptr);
    finishSource->set_call_handler(
      [this](const ua::CallMethodRequest& request,
        std::shared_ptr<const ua::MethodCallContext>
          context,
        std::function<void(ua::CallResult)>
          callback)
      {
        {
          const std::lock_guard lock(mMethodMutex);
          mFinishArguments.assign(request.input_arguments().begin(), request.input_arguments().end());
          mFinishSessionId = context ? context->sessionId : ua::NodeId{};
        }
        ++mFinishCalls;
        if (mIssueCertificate.load())
        {
          ua::CallMethodResult result;
          result.output_arguments().push_back(ua::Variant{mIssuedCertificate->der_encoding()});
          // The request names no password, so the key is returned unprotected (OPC 10000-12 7.9.5).
          result.output_arguments().push_back(ua::Variant{mIssuedKeyPem});
          result.output_arguments().push_back(ua::Variant{ua::Array<ua::ByteString>{}});
          callback(ua::CallResult{std::move(result)});
          return;
        }
        callback(ua::CallResult{ua::StatusCode{ua::Status::BadNothingToDo},
          ua::make_error_detail(
            "ApprovalPending", "the certificate request is awaiting approval", "integration.gds")});
      });

    mGetTrustListMethodId = ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7003}};
    auto getTrustListNode = addressSpace.create_node_sync(mGetTrustListMethodId, ua::NodeClass::Method);
    auto getTrustListMethod = getTrustListNode.as<ua::MethodAccessor>();
    ASSERT_TRUE(getTrustListMethod);
    getTrustListMethod->set_browse_name(ua::QualifiedName{mGdsNamespaceIndex, "GetTrustList"});
    getTrustListMethod->set_display_name(ua::LocalizedText{"", "GetTrustList"});
    getTrustListMethod->set_executable(true);
    directoryNode.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, mGetTrustListMethodId);
    auto* getTrustListSource = mGdsNamespace->find_node<Node>(mGetTrustListMethodId)->method_call_source();
    ASSERT_NE(getTrustListSource, nullptr);
    getTrustListSource->set_call_handler(
      [this](const ua::CallMethodRequest& request,
        std::shared_ptr<const ua::MethodCallContext>,
        std::function<void(ua::CallResult)>
          callback)
      {
        {
          const std::lock_guard lock(mMethodMutex);
          mGetTrustListArguments.assign(request.input_arguments().begin(), request.input_arguments().end());
        }
        ++mGetTrustListCalls;
        ua::CallMethodResult result;
        result.output_arguments().push_back(ua::Variant{
          ua::NodeId{ua::ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList}});
        callback(ua::CallResult{std::move(result)});
      });

    // GetCertificateStatus (Part 12 7.9.10): this stub always requires an update, so every cycle exercises
    // the request path the tests below observe.
    const ua::NodeId statusMethodId{mGdsNamespaceIndex, std::uint32_t{7004}};
    auto statusNode = addressSpace.create_node_sync(statusMethodId, ua::NodeClass::Method);
    auto statusMethod = statusNode.as<ua::MethodAccessor>();
    ASSERT_TRUE(statusMethod);
    statusMethod->set_browse_name(ua::QualifiedName{mGdsNamespaceIndex, "GetCertificateStatus"});
    statusMethod->set_display_name(ua::LocalizedText{"", "GetCertificateStatus"});
    statusMethod->set_executable(true);
    directoryNode.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, statusMethodId);
    auto* statusSource = mGdsNamespace->find_node<Node>(statusMethodId)->method_call_source();
    ASSERT_NE(statusSource, nullptr);
    statusSource->set_call_handler(
      [](const ua::CallMethodRequest&,
        std::shared_ptr<const ua::MethodCallContext>,
        std::function<void(ua::CallResult)>
          callback)
      {
        ua::CallMethodResult result;
        result.output_arguments().push_back(ua::Variant{true});
        callback(ua::CallResult{std::move(result)});
      });
  }

  std::shared_ptr<PullCertificateManagerClientHost> make_host()
  {
    auto impl = CoreClientTestAccess::impl(mClient->core());
    EXPECT_NE(impl, nullptr);
    return std::make_shared<PullCertificateManagerClientHost>(std::weak_ptr<ua::client::CoreClientImpl>(impl),
      impl->executor(),
      impl->client_observer_sink(),
      /*ownCert=*/nullptr,
      ua::Logger{});
  }

  Host::GdsConnectionRequest gds_request()
  {
    Host::GdsConnectionRequest request;
    request.endpointUrl = mEndpointUrl;
    const std::string numericLoopback{"127.0.0.1"};
    const auto hostPosition = request.endpointUrl.find(numericLoopback);
    if (hostPosition != std::string::npos)
    {
      request.endpointUrl.replace(hostPosition, numericLoopback.size(), "localhost");
    }
    request.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
    request.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    request.serverCertificate = mServerCert;
    request.bootstrapTrustStore = mClientCertStore;
    request.anonymousIdentity = true;
    return request;
  }

  template<typename Invoke>
  ua::VoidResult run(Invoke&& invoke)
  {
    std::promise<ua::VoidResult> promise;
    auto future = promise.get_future();
    invoke([&promise](ua::VoidResult result) { promise.set_value(std::move(result)); });
    if (future.wait_for(std::chrono::seconds{10}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the GDS primitive never completed within 10s";
      return ua::VoidResult{ua::StatusCode{ua::Status::BadTimeout}};
    }
    return future.get();
  }

  /// A `run` for the typed GDS reads (Result<optional<DateTime>> / Result<TrustListDataType>).
  template<typename R, typename Invoke>
  R run_result(Invoke&& invoke)
  {
    std::promise<R> promise;
    auto future = promise.get_future();
    invoke([&promise](R result) { promise.set_value(std::move(result)); });
    if (future.wait_for(std::chrono::seconds{10}) != std::future_status::ready)
    {
      ADD_FAILURE() << "the GDS read never completed within 10s";
      return R{ua::StatusCode{ua::Status::BadTimeout}};
    }
    return future.get();
  }

  ua::NodeId default_group() const
  {
    return ua::NodeId{ua::ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup};
  }

  void prepare_issued_certificate()
  {
    ua::Crypto::Name name;
    name.commonName = "Pull-issued replacement client";
    ua::Crypto::SubjectAlternateName alternateName;
    alternateName.hostnames.push_back("localhost");
    alternateName.uris.push_back("urn:test:compliance:client");
    // A GDS returns a key it generated for a request without a password unprotected (OPC 10000-12 7.9.5).
    auto pem = ua::test::unprotected_private_key_pem(ua::CertificateKeyAlgorithm::Rsa);
    ASSERT_TRUE(pem.is_good());
    mIssuedKeyPem = pem.value();
    std::vector<ua::byte> copy(mIssuedKeyPem.size());
    std::memcpy(copy.data(), mIssuedKeyPem.data(), copy.size());
    mIssuedKeys =
      mCrypto->get_private_key_from_pem(ua::CertificateKeyAlgorithm::Rsa, ua::span<ua::byte>{copy});
    ua::Crypto::CreateCertificateConfig parameters;
    parameters.serialNumber = "7301";
    parameters.subject = name;
    parameters.subjectKeys = parameters.issuerKeys = mIssuedKeys;
    parameters.certificateSignatureAlgorithm = ua::CertificateSignatureAlgorithm::RsaPkcs15Sha2256;
    parameters.from = ua::DateTime::now();
    parameters.to = ua::UtcTime{2050, 1, 1, 0, 0, 0};
    parameters.subjectAlternateName = alternateName;
    parameters.keyUsage.digitalSignature = parameters.keyUsage.nonRepudiation =
      parameters.keyUsage.keyEncipherment = parameters.keyUsage.dataEncipherment =
        parameters.keyUsage.serverAuth = parameters.keyUsage.clientAuth = true;
    parameters.basicConstraint.cA = false;
    std::promise<ua::CertificateResult> issued;
    mCrypto->create_certificate_async(
      parameters, [&issued](ua::CertificateResult result) { issued.set_value(std::move(result)); });
    auto certificate = issued.get_future().get();
    ASSERT_TRUE(certificate.is_good()) << ua::to_string(certificate.status_code());
    mIssuedCertificate = certificate.value();
    mServerCertStore->add_to_trusted_certificates_sync(mIssuedCertificate);
    // This in-tree server doubles as the GDS. Its exported TrustList must retain the server certificate as a
    // client trust anchor when the manager atomically replaces the runtime store, otherwise the subsequent
    // reconnect would correctly reject the self-signed server before reaching the Session-transfer oracle.
    mServerCertStore->add_to_trusted_certificates_sync(mServerCert);
    mIssueCertificate.store(true);
  }

  ua::ByteString mIssuedKeyPem;  ///< the unprotected PEM FinishRequest returns
  std::shared_ptr<default_ns::Namespace> mGdsNamespace;
  std::uint16_t mGdsNamespaceIndex{0};
  ua::NodeId mDirectoryId;
  ua::NodeId mStartMethodId;
  ua::NodeId mFinishMethodId;
  ua::NodeId mGetTrustListMethodId;
  std::atomic<std::size_t> mStartCalls{0};
  std::atomic<std::size_t> mFinishCalls{0};
  std::atomic<std::size_t> mGetTrustListCalls{0};
  std::mutex mMethodMutex;
  std::vector<ua::Variant> mStartArguments;
  std::vector<ua::Variant> mFinishArguments;
  std::vector<ua::Variant> mGetTrustListArguments;
  ua::NodeId mStartSessionId;
  ua::NodeId mFinishSessionId;
  std::atomic<bool> mIssueCertificate{false};
  std::shared_ptr<const ua::AsymmetricKeyPair> mIssuedKeys;
  std::shared_ptr<const ua::X509Certificate> mIssuedCertificate;
};

// The GDS bootstrap opens a real SignAndEncrypt + Anonymous channel to the reference server, its cert
// validated against the bootstrap trust store. Falsifiable: the old DEFER-STUB returned Bad_NotImplemented;
// a wrong policy / mode / untrusted cert would fail the open.
// @verifies CL-PULLCRT-001
// @verifies CL-PULLCRT-002
// @relation(CL-PULLCRT-001, CL-PULLCRT-002, scope=function)
TEST_F(ClientPullCertGds, OpensSignAndEncryptAnonymousGdsChannel)
{
  auto host = make_host();

  const auto opened = run([&](auto cb) { host->open_gds_connection_async(gds_request(), std::move(cb)); });
  EXPECT_TRUE(opened.is_good())
    << "the SignAndEncrypt + Anonymous GDS channel must open (CL-PULLCRT-001/002): "
    << ua::to_string(opened.status_code());

  // Closing the GDS Connection is a clean best-effort Good.
  const auto closed = run([&](auto cb) { host->close_gds_connection_async(std::move(cb)); });
  EXPECT_TRUE(closed.is_good());
}

// Highest production tier: public Client::start_pull_cert_management_sync constructs the real manager and GDS
// host. TestAccess only observes the strand-owned armed delay; it does not invoke the implementation.
// @verifies CL-DISC-017
// @relation(CL-DISC-017, scope=function)
TEST_F(ClientPullCertGds, PublicManagerArmsRequiredRandomizedRegularCycleDelay)
{
  ua::client::PullCertManagementConfig config;
  config.gdsEndpointUrl = mEndpointUrl;
  const std::string numericLoopback{"127.0.0.1"};
  const auto hostPosition = config.gdsEndpointUrl.find(numericLoopback);
  ASSERT_NE(hostPosition, std::string::npos);
  config.gdsEndpointUrl.replace(hostPosition, numericLoopback.size(), "localhost");
  config.bootstrapTrustStore = mClientCertStore;
  config.runtimeCertStore = mClientCertStore;
  config.gdsSecurityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  config.gdsServerCertificate = mServerCert;
  config.updateFrequency = std::chrono::seconds{60};

  auto manager = mClient->start_pull_cert_management_sync(std::move(config));
  ASSERT_NE(manager, nullptr);
  auto managerImpl = PullAccess::impl(*manager);
  ASSERT_NE(managerImpl, nullptr);

  std::optional<std::chrono::milliseconds> armedDelay;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
  while (!armedDelay && std::chrono::steady_clock::now() < deadline)
  {
    std::promise<std::optional<std::chrono::milliseconds>> promise;
    auto future = promise.get_future();
    PullAccess::last_armed_cycle_delay_async(
      managerImpl, [&promise](std::optional<std::chrono::milliseconds> delay) { promise.set_value(delay); });
    ASSERT_EQ(future.wait_for(std::chrono::seconds{2}), std::future_status::ready);
    armedDelay = future.get();
    if (!armedDelay)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
  }

  ASSERT_TRUE(armedDelay.has_value()) << "public PullManagement bootstrap did not arm its regular cycle";
  EXPECT_GE(*armedDelay, std::chrono::milliseconds{60'600});
  EXPECT_LE(*armedDelay, std::chrono::milliseconds{66'000});

  const auto stopped = run([&](auto callback) { manager->stop_async(std::move(callback)); });
  EXPECT_TRUE(stopped.is_good());
}

// @verifies CL-PULLCRT-006
// @verifies CL-PULLCRT-005
// Highest public tier: a TrustList-only manager downloads and commits the live
// GDS TrustList, then broadcasts immediate revalidation to the Client registry.
// @relation(CL-PULLCRT-005, CL-PULLCRT-006, scope=function)
TEST_F(ClientPullCertGds, PublicTrustListOnlyCycleCommitsThenRevalidatesConnections)
{
  auto observer = std::make_shared<PullLifecycleObserver>();
  mClient->set_security_observer(observer);

  ua::client::PullCertManagementConfig config;
  config.gdsEndpointUrl = mEndpointUrl;
  const std::string numericLoopback{"127.0.0.1"};
  const auto hostPosition = config.gdsEndpointUrl.find(numericLoopback);
  ASSERT_NE(hostPosition, std::string::npos);
  config.gdsEndpointUrl.replace(hostPosition, numericLoopback.size(), "localhost");
  config.bootstrapTrustStore = mClientCertStore;
  config.runtimeCertStore = mClientCertStore;
  config.gdsSecurityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  config.gdsServerCertificate = mServerCert;
  config.renewApplicationCertificate = false;

  auto manager = mClient->start_pull_cert_management_sync(std::move(config));
  ASSERT_NE(manager, nullptr);
  auto cyclePromise = std::make_shared<std::promise<ua::VoidResult>>();
  auto cycleFuture = cyclePromise->get_future();
  manager->force_cycle_async(
    [cyclePromise](ua::VoidResult result) { cyclePromise->set_value(std::move(result)); });
  ASSERT_EQ(cycleFuture.wait_for(30s), std::future_status::ready)
    << "the real secured GDS download/apply/revalidation cycle did not complete";
  const auto cycle = cycleFuture.get();
  ASSERT_TRUE(cycle.is_good());

  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while ((observer->trustListCommitted.load() == 0 || observer->revalidationCompleted.load() == 0) &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(10ms);
  }
  EXPECT_EQ(observer->trustListCommitted.load(), 1);
  EXPECT_EQ(observer->revalidationCompleted.load(), 1);
  EXPECT_EQ(manager->pull_cert_info()->state, ua::client::PullCertManagementState::Idle);

  const auto stopped = run([&](auto callback) { manager->stop_async(std::move(callback)); });
  EXPECT_TRUE(stopped.is_good());
}

// @verifies CL-RECONN-006
// Highest public tier: a public PullCertificateManager receives a fresh key pair + self-signed application
// certificate from the real secured GDS Method path, commits it to the runtime store, and broadcasts the
// own-certificate update. A separately active public Connection with a real server Subscription must then
// reconnect under CertRotated, create a new Session, and transfer that Subscription.
// @relation(CL-RECONN-006, scope=function)
// @relation(AC-CL-RECONN-006-01, scope=function)
TEST_F(ClientPullCertGds, PublicOwnCertificateUpdateCreatesSessionAndTransfersSubscription)
{
  prepare_issued_certificate();

  ua::client::ConnectionConfig connectionConfig;
  connectionConfig.endpointUrl = mEndpointUrl;
  connectionConfig.securityMode = ua::MessageSecurityMode::SignAndEncrypt;
  connectionConfig.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  connectionConfig.serverCertificate = mServerCert;
  auto connection = mClient->connect_sync(std::move(connectionConfig));
  auto observer = std::make_shared<CertificateReconnectObserver>();
  connection.set_connection_observer(observer);
  const auto initialSession = connection.session_id();
  ASSERT_TRUE(initialSession.is_good());
  auto subscription =
    connection.subscriptions().try_create_sync(ua::client::SubscriptionConfig{.publishingIntervalMs = 50.0});
  ASSERT_TRUE(subscription.is_good());

  ua::client::PullCertManagementConfig config;
  config.gdsEndpointUrl = mEndpointUrl;
  const std::string numericLoopback{"127.0.0.1"};
  const auto hostPosition = config.gdsEndpointUrl.find(numericLoopback);
  ASSERT_NE(hostPosition, std::string::npos);
  config.gdsEndpointUrl.replace(hostPosition, numericLoopback.size(), "localhost");
  config.bootstrapTrustStore = mClientCertStore;
  config.runtimeCertStore = mClientCertStore;
  config.gdsSecurityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  config.gdsServerCertificate = mServerCert;
  config.applicationId = ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7201}};
  config.pollInitialDelay = 1ms;
  config.pollMaxRepeat = 1;
  config.pollBackoffMultiplier = 1.0;
  config.pollJitterPct = 0.0;
  ua::client::CertificateGroupConfig group;
  group.useNewKeyPair = true;
  config.certificateGroups.push_back(std::move(group));

  auto manager = mClient->start_pull_cert_management_sync(std::move(config));
  ASSERT_NE(manager, nullptr);
  auto cyclePromise = std::make_shared<std::promise<ua::VoidResult>>();
  auto cycleFuture = cyclePromise->get_future();
  manager->force_cycle_async(
    [cyclePromise](ua::VoidResult result) { cyclePromise->set_value(std::move(result)); });
  ASSERT_EQ(cycleFuture.wait_for(30s), std::future_status::ready);
  ASSERT_TRUE(cycleFuture.get().is_good());
  if (const auto info = manager->pull_cert_info(); info->lastError)
    FAIL() << "the cycle did not commit the delivered certificate: " << ua::to_string(*info->lastError);

  const auto reconnectDeadline = std::chrono::steady_clock::now() + 15s;
  while (!observer->reconnected.load() && std::chrono::steady_clock::now() < reconnectDeadline)
    std::this_thread::sleep_for(10ms);
  ASSERT_TRUE(observer->reconnected.load())
    << "the own-certificate commit must drive the active public Connection back to Active";
  EXPECT_GE(observer->certRotatedAttempts.load(), 1);
  {
    const std::lock_guard lock(observer->mutex);
    ASSERT_TRUE(observer->outcome.has_value());
    EXPECT_FALSE(observer->outcome->sessionPreserved);
    EXPECT_TRUE(observer->outcome->subscriptionsTransferred);
  }
  const auto replacementSession = connection.session_id();
  ASSERT_TRUE(replacementSession.is_good());
  EXPECT_NE(replacementSession.value(), initialSession.value());

  EXPECT_TRUE(run([&](auto callback) { manager->stop_async(std::move(callback)); }).is_good());
  connection.close_sync();
}

// @verifies CL-PULLCRT-003
// @verifies CL-PULLCRT-004
// Highest public tier: the public manager resolves and invokes the Part 12 StartNewKeyPairRequest and
// FinishRequest Methods on a real secured GDS channel. Repeated Bad_NothingToDo responses remain
// approval-pending, stop exactly at the configured burst bound, retain the NodeId requestId, and return the
// cycle to Idle.
// @relation(CL-PULLCRT-003, CL-PULLCRT-004, scope=function)
TEST_F(ClientPullCertGds, PublicManagerBoundsFinishRequestApprovalPolling)
{
  ua::client::PullCertManagementConfig config;
  config.gdsEndpointUrl = mEndpointUrl;
  const std::string numericLoopback{"127.0.0.1"};
  const auto hostPosition = config.gdsEndpointUrl.find(numericLoopback);
  ASSERT_NE(hostPosition, std::string::npos);
  config.gdsEndpointUrl.replace(hostPosition, numericLoopback.size(), "localhost");
  config.bootstrapTrustStore = mClientCertStore;
  config.runtimeCertStore = mClientCertStore;
  config.gdsSecurityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  config.gdsServerCertificate = mServerCert;
  config.applicationId = ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7200}};
  config.pollInitialDelay = 1ms;
  config.pollMaxRepeat = 2;
  config.pollBackoffMultiplier = 1.0;
  config.pollJitterPct = 0.0;
  ua::client::CertificateGroupConfig group;
  group.useNewKeyPair = true;
  config.certificateGroups.push_back(std::move(group));

  auto manager = mClient->start_pull_cert_management_sync(std::move(config));
  ASSERT_NE(manager, nullptr);
  auto cyclePromise = std::make_shared<std::promise<ua::VoidResult>>();
  auto cycleFuture = cyclePromise->get_future();
  manager->force_cycle_async(
    [cyclePromise](ua::VoidResult result) { cyclePromise->set_value(std::move(result)); });
  ASSERT_EQ(cycleFuture.wait_for(30s), std::future_status::ready);
  ASSERT_TRUE(cycleFuture.get().is_good());

  EXPECT_EQ(mStartCalls.load(), 1U);
  EXPECT_EQ(mFinishCalls.load(), 2U);
  EXPECT_GE(mGetTrustListCalls.load(), 1U);
  EXPECT_EQ(manager->pull_cert_info()->state, ua::client::PullCertManagementState::Idle);
  ASSERT_EQ(manager->pull_cert_info()->pendingRequests.size(), 1U);
  const auto clientImpl = CoreClientTestAccess::impl(mClient->core());
  ASSERT_NE(clientImpl, nullptr);
  const auto pullHost = CoreClientTestAccess::pull_cert_host(*clientImpl);
  ASSERT_NE(pullHost, nullptr);
  EXPECT_FALSE(pullHost->current_own_cert_thumbprint_sha1().empty())
    << "the persisted request must be bound to the certificate selected for the live GDS channel";
  EXPECT_EQ(manager->pull_cert_info()->pendingRequests[0].requestId,
    (ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7100}}));
  {
    const std::lock_guard lock(mMethodMutex);
    ASSERT_EQ(mStartArguments.size(), 7U);
    // RATIFIED EXPECTATION CHANGE (2026-10-03, decisions D4 + D5): this arm asserted one argument, the local
    // ServerConfiguration DefaultApplicationGroup. OPC 10000-12 7.9.9 is GetTrustList(applicationId,
    // certificateGroupId), and a default CertificateGroupConfig names the GDS's default group with a null
    // NodeId (7.9.3: "If null the CertificateManager shall choose the DefaultApplicationGroup").
    ASSERT_EQ(mGetTrustListArguments.size(), 2U);
    EXPECT_EQ(
      mGetTrustListArguments[0].as<ua::NodeId>(), (ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7200}}));
    EXPECT_TRUE(mGetTrustListArguments[1].as<ua::NodeId>().is_null());
    EXPECT_EQ(mStartArguments[0].as<ua::NodeId>(), (ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7200}}));
    ASSERT_EQ(mFinishArguments.size(), 2U);
    EXPECT_EQ(mFinishArguments[0].as<ua::NodeId>(), (ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7200}}));
    EXPECT_EQ(mFinishArguments[1].as<ua::NodeId>(), (ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7100}}));
    EXPECT_FALSE(mStartSessionId.is_null());
    EXPECT_EQ(mFinishSessionId, mStartSessionId)
      << "Start and Finish must use the same secured Session and therefore the same client certificate";
  }

  EXPECT_TRUE(run([&](auto callback) { manager->stop_async(std::move(callback)); }).is_good());
}

// section 3.1 (stop-races-open leak guard): once close_gds has latched the closing flag, a later successful
// open must close-instead-of-stash and report closed_during_open - never leave a stashed session lingering
// past stop. Exercises the success-branch leak guard (a real connect succeeds, then is closed rather than
// stashed).
// @verifies CL-PULLCRT-002
// @relation(CL-PULLCRT-002, scope=function)
TEST_F(ClientPullCertGds, OpenAfterCloseIsRejectedClosedDuringOpen)
{
  auto host = make_host();

  const auto closed = run([&](auto cb) { host->close_gds_connection_async(std::move(cb)); });
  EXPECT_TRUE(closed.is_good());

  const auto opened = run([&](auto cb) { host->open_gds_connection_async(gds_request(), std::move(cb)); });
  EXPECT_TRUE(opened.is_bad())
    << "an open after a close (mGdsClosing latched) must not stash a lingering session";
  ASSERT_NE(opened.shared_detail(), nullptr);
  EXPECT_EQ(opened.shared_detail()->source, "client.tier1.pull_cert.open_gds.closed_during_open");
}

// section 3.1: a second successful open drives the REAL displace-and-close success branch (toClose =
// std::move(mGdsConnection); gds_close_and_forget(toClose)) against a live server, and both opens succeed.
// This pins that the displace path is crash-/deadlock-/UAF-safe - a broken guard (closing under mGdsMutex ->
// deadlock, or moving the shared_ptr without the raw-pointer snapshot -> use-after-free in
// gds_close_and_forget) fails here (the 10s run() bound catches a hang). Scope note: the actual server-side
// close of the displaced session is FIRE-AND-FORGET and `ua::client::Connection` exposes no observable-close
// interface (it is a concrete move-only pimpl), so this test does NOT - and cannot - assert the displaced
// session was closed; that the displace branch routes through gds_close_and_forget is a section 3.1-logic
// guarantee, and the best-effort close is the accepted Connection-close-observability limitation
// (OPEN-PULLCRT-teardown-close). The closed_during_open sibling test IS falsifiable for the
// close-instead-of-stash branch (it asserts the exact source tag).
// @verifies CL-PULLCRT-002
// @relation(CL-PULLCRT-002, scope=function)
TEST_F(ClientPullCertGds, DoubleOpenDriveTheDisplacePathSafely)
{
  auto host = make_host();

  const auto first = run([&](auto cb) { host->open_gds_connection_async(gds_request(), std::move(cb)); });
  EXPECT_TRUE(first.is_good());
  const auto second = run([&](auto cb) { host->open_gds_connection_async(gds_request(), std::move(cb)); });
  EXPECT_TRUE(second.is_good()) << "the second open drives the displace-and-close path and must still "
                                   "succeed (no deadlock / UAF / crash)";

  const auto closed = run([&](auto cb) { host->close_gds_connection_async(std::move(cb)); });
  EXPECT_TRUE(closed.is_good());
}

// Slice B: over the open GDS channel, read TrustList.LastUpdateTime from the reference server's
// default-application-group TrustListType (Part 12 section 7.8.2.1 - the conditional-download SKIP check).
// This is the E2E-working half of CL-PULLCRT-005. Falsifiable: the old stub returned Bad_NotImplemented; a
// wrong node fails the read.
TEST_F(ClientPullCertGds, ReadsTrustListLastUpdateTimeOverGds)
{
  auto host = make_host();
  ASSERT_TRUE(run([&](auto cb) { host->open_gds_connection_async(gds_request(), std::move(cb)); }).is_good());

  // Good with a DateTime, or Good/nullopt if the server publishes none (the skip marker).
  const auto lastUpdate = run_result<ua::Result<std::optional<ua::DateTime>>>(
    [&](auto cb)
    {
      host->read_trust_list_last_update_time_async(
        ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7200}}, default_group(), std::move(cb));
    });
  EXPECT_TRUE(lastUpdate.is_good()) << "reading TrustList.LastUpdateTime over the GDS channel must succeed: "
                                    << ua::to_string(lastUpdate.status_code());

  const auto closed = run([&](auto cb) { host->close_gds_connection_async(std::move(cb)); });
  EXPECT_TRUE(closed.is_good());
}

// @verifies CL-FILE-001
// Full TrustList DOWNLOAD over the GDS channel, end-to-end: read_trust_list_async runs the file-transfer
// Open->Read->Close chain against the reference server's DefaultApplicationGroup TrustList File and decodes
// the UA-Binary TrustListDataType body. This is a genuine end-to-end exercise of CL-FILE-001 (Open obtains a
// real server fileHandle, the read_all loop reads it, the handle's RAII drop Closes it) AND the
// FileTransferClient instance-method resolution fix - FileTransferClient now resolves the file object's
// INSTANCE Open/Read/Close method nodes via TranslateBrowsePaths and Calls them (OPC 10000-4 section 5.11.2),
// rather than the abstract FileType methodId the reference server (which registers the handler at the
// instance node ..._TrustList_Open) rejects. A plain Open reads the whole file, so the server encodes
// specifiedLists = 0x0F (all four lists, TrustListManager sMaskAll). Falsifiable: the pre-fix abstract-method
// call returned Bad_NotSupported here; a masked/crashing RPC or a wrong specifiedLists fails.
// @relation(CL-FILE-001, scope=function)
TEST_F(ClientPullCertGds, DownloadsTrustListOverGds)
{
  auto host = make_host();
  ASSERT_TRUE(run([&](auto cb) { host->open_gds_connection_async(gds_request(), std::move(cb)); }).is_good());

  const auto trustList = run_result<ua::Result<ua::TrustListDataType>>(
    [&](auto cb)
    {
      host->read_trust_list_async(
        ua::NodeId{mGdsNamespaceIndex, std::uint32_t{7200}}, default_group(), std::move(cb));
    });
  ASSERT_TRUE(trustList.is_good()) << "the TrustList download over the GDS channel must succeed (instance "
                                      "Open/Read/Close resolved + decoded): "
                                   << ua::to_string(trustList.status_code());
  EXPECT_EQ(trustList.value().specified_lists(), 0x0Fu)
    << "a full TrustList read encodes all four lists (TrustListManager sMaskAll)";

  const auto closed = run([&](auto cb) { host->close_gds_connection_async(std::move(cb)); });
  EXPECT_TRUE(closed.is_good());
}

// Part 12 section 7: the pull-management session authenticates with the client's APPLICATION INSTANCE
// CERTIFICATE on the channel, from which the server derives ApplicationSelfAdmin. So the channel must be
// SignAndEncrypt (the exchange carries key material) AND the UserIdentityToken must be Anonymous - a user
// identity would be a second, irrelevant credential. Both conjuncts are exactly what a plausible
// implementation gets wrong, because each looks like ordinary configuration to be honoured: it threads
// whatever identity is configured elsewhere, and it honours a caller-supplied SecurityMode. This test
// therefore deliberately REQUESTS the weaker Sign mode - ComplianceSecured's server really does publish a
// Basic256Sha256/Sign endpoint, so a manager that honoured the request would connect *successfully* on a Sign
// channel and be caught by the observation rather than merely failing to connect. The observation is taken
// SERVER-SIDE from the MethodCallContext of the GetTrustList Call the real cycle makes over the channel the
// production code opened (channelSecurityMode is the negotiated channel's mode; clientUserId is "anonymous"
// only when AnonymousAuthenticator accepted an Anonymous token - every other token kind it rejects), so
// nothing in this test sets the mode or the token it asserts on.
// @verifies AC-CL-PULLCRT-002-MANAGEMENT-CHANNEL
TEST_F(ClientPullCertGds, PullManagementChannelIsSignAndEncryptWithAnonymousUser)
{
  struct ChannelObservation
  {
    std::mutex mutex;
    bool called{false};
    bool contextPresent{false};
    ua::MessageSecurityMode mode{ua::MessageSecurityMode::Invalid};
    ua::String userId;
  };

  auto observed = std::make_shared<ChannelObservation>();

  // Re-install the GetTrustList handler so it records the channel facts of the call the cycle makes; it
  // still answers with the same TrustList NodeId as the fixture's handler, so the cycle proceeds normally.
  auto* getTrustListSource = mGdsNamespace->find_node<Node>(mGetTrustListMethodId)->method_call_source();
  ASSERT_NE(getTrustListSource, nullptr);
  getTrustListSource->set_call_handler(
    [this, observed](const ua::CallMethodRequest& request,
      std::shared_ptr<const ua::MethodCallContext>
        context,
      std::function<void(ua::CallResult)>
        callback)
    {
      {
        const std::lock_guard lock(mMethodMutex);
        mGetTrustListArguments.assign(request.input_arguments().begin(), request.input_arguments().end());
      }
      {
        const std::lock_guard lock(observed->mutex);
        observed->called = true;
        observed->contextPresent = static_cast<bool>(context);
        if (context)
        {
          observed->mode = context->channelSecurityMode;
          observed->userId = context->clientUserId;
        }
      }
      ++mGetTrustListCalls;
      ua::CallMethodResult result;
      result.output_arguments().push_back(ua::Variant{
        ua::NodeId{ua::ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList}});
      callback(ua::CallResult{std::move(result)});
    });

  ua::client::PullCertManagementConfig config;
  config.gdsEndpointUrl = mEndpointUrl;
  const std::string numericLoopback{"127.0.0.1"};
  const auto hostPosition = config.gdsEndpointUrl.find(numericLoopback);
  ASSERT_NE(hostPosition, std::string::npos);
  config.gdsEndpointUrl.replace(hostPosition, numericLoopback.size(), "localhost");
  config.bootstrapTrustStore = mClientCertStore;
  config.runtimeCertStore = mClientCertStore;
  config.gdsSecurityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  config.gdsServerCertificate = mServerCert;
  config.renewApplicationCertificate = false;
  // The weakening attempt the obligation must refuse; the server offers a real Sign endpoint.
  config.requestedGdsSecurityMode = ua::MessageSecurityMode::Sign;

  auto manager = mClient->start_pull_cert_management_sync(std::move(config));
  ASSERT_NE(manager, nullptr);
  auto cyclePromise = std::make_shared<std::promise<ua::VoidResult>>();
  auto cycleFuture = cyclePromise->get_future();
  manager->force_cycle_async(
    [cyclePromise](ua::VoidResult result) { cyclePromise->set_value(std::move(result)); });
  ASSERT_EQ(cycleFuture.wait_for(30s), std::future_status::ready)
    << "the real secured GDS cycle did not complete";
  const auto cycle = cycleFuture.get();
  EXPECT_TRUE(cycle.is_good()) << "the pull-management cycle must run over the forced SignAndEncrypt + "
                                  "Anonymous GDS channel: "
                               << ua::to_string(cycle.status_code());

  {
    const std::lock_guard lock(observed->mutex);
    ASSERT_TRUE(observed->called)
      << "no GDS Method was called over the management channel, so nothing was observed";
    ASSERT_TRUE(observed->contextPresent)
      << "the GDS Method call carried no session context, so the channel facts are unobservable";
    EXPECT_EQ(observed->mode, ua::MessageSecurityMode::SignAndEncrypt)
      << "pull management must run on a SignAndEncrypt channel regardless of any weaker requested mode, "
         "observed: "
      << ua::to_string(observed->mode);
    EXPECT_EQ(observed->userId, ua::String{"anonymous"})
      << "pull management must present an Anonymous UserIdentityToken (the channel certificate is the "
         "authentication carrier)";
  }

  const auto stopped = run([&](auto callback) { manager->stop_async(std::move(callback)); });
  EXPECT_TRUE(stopped.is_good());
}

}  // namespace
