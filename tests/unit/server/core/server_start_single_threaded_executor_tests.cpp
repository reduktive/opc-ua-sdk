// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_certificate_push_service.h"
#include "ua_certificate_store_files.h"
#include "ua_crypto.h"
#include "ua_security_policy.h"
#include "ua_server_configuration.h"
#include "ua_server_impl.h"

#include "server_impl_test_access.h"
#include "ua_to_string.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <optional>
#include <string_view>

#include "test_components.h"
#include "fake_certificate_store.h"
#include "test_key_cache.h"
#include "test_pki_helpers.h"

namespace
{
using namespace std::chrono_literals;
using ua::CertificateStore;
using ua::CertificateStoreFiles;
using ua::CertificateType;
using ua::Crypto;
using ua::Guid;
using ua::shared_ptr;
using ua::TrustListValidationOptions;
using ua::UtcTime;
using ua::server::ServerImpl;

// A server whose executor has ONE worker, whose certificate store shares that executor, and which
// has at least one endpoint requiring certificates.
//
// That combination used to never finish starting. `ServerImpl::validate_endpoint_certificates`
// called `try_get_application_certificates_sync()` from the start continuation, which runs ON the
// executor. The wrapper posts to the store's executor and blocks on the future, so the single
// worker was waiting for work only it could have run. No timeout, no error - the start simply
// never completed.
//
// Handing the certificate store the same executor as the server is a natural thing for an embedded
// or single-threaded integrator to do, and nothing in the API warns against it.
// Bounded like every other wait in this file: teardown must not be able to hang the binary either.
void shutdown(ServerImpl& server)
{
  std::promise<ua::VoidResult> stopped;
  auto stoppedFuture = stopped.get_future();
  server.shutdown_async({}, [&stopped](ua::VoidResult result) { stopped.set_value(std::move(result)); });
  EXPECT_EQ(stoppedFuture.wait_for(30s), std::future_status::ready) << "shutdown did not complete";
}

struct SingleThreadedStartFixture : ::testing::Test
{
  // ONE worker. The whole point: with two, the fetch is serviced by the other and nothing hangs.
  //
  // Held by pointer so it can be DELIBERATELY LEAKED when the server fails to start. A regression
  // here leaves the single worker blocked forever inside a future::get() that only that worker
  // could satisfy, and `join()` on a pool whose worker cannot return never comes back - so a
  // fixture that always joins converts a clean 30-second test failure into a hung binary that
  // reports nothing. That is the failure mode this defect hid behind for as long as it did, and
  // the design note (section 5) names it explicitly. On the success path the pool is stopped and
  // joined normally; the leak happens only when the suite is already reporting a failure.
  std::unique_ptr<boost::asio::thread_pool> pool{std::make_unique<boost::asio::thread_pool>(1)};
  bool workerIsJoinable{false};
  shared_ptr<const Crypto> crypto;
  shared_ptr<CertificateStore> certStore;
  std::filesystem::path tempDir;

  void SetUp() override
  {
    // The password callback is not optional here: creating a self-signed application instance
    // certificate writes an encrypted private key, and without a supplier the create fails and the
    // fixture never reaches the thing under test.
    crypto = ua::create_default_crypto([]() { return ua::SecureString{"password"}; });

    Crypto::Name subject;
    subject.commonName = "Single Threaded Start";
    UtcTime expiry{2050, 1, 1, 0, 0, 0};
    Crypto::SubjectAlternateName altName;
    altName.uris.push_back("urn:test:server");

    auto certResult = crypto->try_create_self_signed_application_instance_certificate_sync(
      subject, expiry, altName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(certResult.is_good()) << "could not create a self-signed application certificate";
    auto [keys, cert] = std::move(certResult).value();

    tempDir = std::filesystem::temp_directory_path() /
              ("ua_single_threaded_start_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(tempDir);

    // THE SHAPE UNDER TEST: the store is given the server's own executor.
    certStore = CertificateStoreFiles::create(pool->executor(), crypto, {.trustListPath = tempDir});

    CertificateStore::ApplicationCertificate appCert;
    appCert.certificateType = CertificateType::RsaSha256Application;
    appCert.certificate = cert;
    appCert.keys = keys;
    certStore->add_to_application_certificates_sync(appCert);
  }

  void TearDown() override
  {
    if (workerIsJoinable)
    {
      pool->stop();
      pool->join();
    }
    else
    {
      // Intentional: see the declaration. Never join a worker that cannot return.
      static_cast<void>(pool.release());
    }
    std::error_code ec;
    std::filesystem::remove_all(tempDir, ec);
  }

  shared_ptr<ServerImpl> make_server()
  {
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;

    ::ua::server::CombinedConfig frozen;
    frozen.identity = ua::ApplicationIdentity::load_default();
    frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

    ::ua::server::ServerConfig sc;
    {
      ::ua::server::ServerConfig::ListenerConfig listener;
      listener.name = "SingleThreadedListener";
      listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
      // Port 0: the kernel picks a free one, so a stray server elsewhere on this machine cannot
      // turn a deadlock regression into a bind failure and mask what this test is measuring.
      listener.bind.address = "127.0.0.1:0";

      // A secured endpoint is what makes required_certificate_types() non-empty, and therefore
      // what makes the start path consult the certificate store at all.
      ua::server::ServerEndpointConfig epAuth;
      epAuth.name = "Basic256Sha256_Sign";
      epAuth.messageSecurityMode = ua::MessageSecurityMode::Sign;
      epAuth.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
      epAuth.userIdentityTokens.push_back(
        ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
      listener.endpoints.push_back(std::move(epAuth));

      sc.listeners().push_back(std::move(listener));
    }
    sc.validate();
    frozen.server = std::move(sc);

    auto server = ServerImpl::create(pool->executor(),
      std::move(frozen),
      ua::server::ServerComponents{.crypto = crypto, .applicationGroupCertificateStore = certStore});
    ua::test_helpers::ServerImplTestAccess{*server}.initialise_listeners_from_config();
    return server;
  }
};

// @verifies AC-SVR-BASE-START-NO-BLOCKING-CERT-FETCH
//
// The assertion is against a BOUNDED wait, deliberately. A deadlock test that itself deadlocks
// teaches nothing and takes the whole binary down with it - which is exactly the failure mode this
// defect hid behind for as long as it did, so it must not be reintroduced by the test that proves
// it fixed. `wait_for` fails; it never hangs.
TEST_F(SingleThreadedStartFixture, StartCompletesWhenTheCertificateStoreSharesTheOneWorker)
{
  auto server = make_server();

  std::promise<ua::VoidResult> started;
  auto startedFuture = started.get_future();
  server->start_async([&started](ua::VoidResult result) { started.set_value(std::move(result)); });

  ASSERT_EQ(startedFuture.wait_for(30s), std::future_status::ready)
    << "start never completed on a single-threaded executor shared with the certificate store. "
       "The start path is blocking a worker on a _sync wrapper whose async work needs that same "
       "worker";

  workerIsJoinable = true;  // the worker returned, so the pool can be joined in TearDown
  auto result = startedFuture.get();
  EXPECT_TRUE(result.is_good()) << "start failed: " << ua::to_string(result.status_code());

  shutdown(*server);
}

// The server hands its own Session lookup to the push service it wires: a trust-list claim by a Session
// the server does not hold is refused, so a modification that lands after its Session closed opens no
// transaction. Driven through the server's wiring, not an injected lookup.
// @verifies AC-SVR-SECADMIN-009-TRUST-LIST-CHANGES-ARE-REFUSED-UNDER-ANOTHER-SESSIONS-TRANSACTION
TEST_F(SingleThreadedStartFixture, TheServerWiresItsSessionLookupIntoThePushService)
{
  auto server = make_server();

  std::promise<ua::VoidResult> started;
  auto startedFuture = started.get_future();
  server->start_async([&started](ua::VoidResult result) { started.set_value(std::move(result)); });
  ASSERT_EQ(startedFuture.wait_for(30s), std::future_status::ready);
  workerIsJoinable = true;
  ASSERT_TRUE(startedFuture.get().is_good());

  auto push = ua::test_helpers::ServerImplTestAccess{*server}.certificate_push_service();
  ASSERT_NE(push, nullptr) << "a server with a certificate store and a crypto backend wires push management";
  EXPECT_EQ(push->claim_trust_list_modification(ua::NodeId{1, ua::Guid::create_and_generate()})
              .status_code()
              .as_status(),
    ua::Status::BadSessionIdInvalid)
    << "a Session the server does not hold takes no claim";

  shutdown(*server);
}

// The fast path must stay synchronous: an endpoint set needing no certificate must not acquire a
// post. Asserted by the same bounded wait, so a regression that makes the no-security case depend
// on the executor being free shows up here rather than in a customer's embedded build.
TEST_F(SingleThreadedStartFixture, StartCompletesWithNoSecuredEndpointAndNoCertificateFetch)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "NoneOnlyListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:0";

    ua::server::ServerEndpointConfig epNone;
    epNone.name = "None";
    epNone.messageSecurityMode = ua::MessageSecurityMode::None;
    epNone.securityPolicyId = ua::SecurityPolicyId::None;
    epNone.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(epNone));

    sc.listeners().push_back(std::move(listener));
  }
  sc.validate();
  frozen.server = std::move(sc);

  auto server = ServerImpl::create(pool->executor(),
    std::move(frozen),
    ua::server::ServerComponents{.crypto = crypto, .applicationGroupCertificateStore = certStore});
  ua::test_helpers::ServerImplTestAccess{*server}.initialise_listeners_from_config();

  std::promise<ua::VoidResult> started;
  auto startedFuture = started.get_future();
  server->start_async([&started](ua::VoidResult result) { started.set_value(std::move(result)); });

  ASSERT_EQ(startedFuture.wait_for(30s), std::future_status::ready)
    << "a None-only server must start without consulting the certificate store at all";
  workerIsJoinable = true;
  EXPECT_TRUE(startedFuture.get().is_good());

  shutdown(*server);
}

// THE DEFAULT CONFIGURATION, and the reason this defect matters more than it first appeared.
//
// Supplying no certificate store does NOT mean there is no store: create() substitutes its own
// CertificateStoreFiles built on mExecutor - the SERVER'S OWN EXECUTOR. So the shape that
// deadlocked was never an exotic choice by an integrator who shared an executor deliberately. It
// is what you get by default, from examples/reference_server's own construction pattern, on any
// single-threaded server with a secured endpoint.
//
// The assertion is COMPLETION, not success: with an empty default store the start legitimately
// fails with BadConfigurationError because the required certificate is missing. A definite answer
// either way is the property under test. Hanging is the only wrong outcome.
TEST_F(SingleThreadedStartFixture, DefaultSubstitutedStoreOnTheServerExecutorStillCompletesTheStart)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  ::ua::server::ServerConfig sc;
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "DefaultStoreListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:0";

    ua::server::ServerEndpointConfig epAuth;
    epAuth.name = "Basic256Sha256_Sign";
    epAuth.messageSecurityMode = ua::MessageSecurityMode::Sign;
    epAuth.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    epAuth.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(epAuth));

    sc.listeners().push_back(std::move(listener));
  }
  sc.validate();
  frozen.server = std::move(sc);

  // No store supplied: create() builds one on pool's single-worker executor.
  auto server =
    ServerImpl::create(pool->executor(), std::move(frozen), ua::server::ServerComponents{.crypto = crypto});
  ua::test_helpers::ServerImplTestAccess{*server}.initialise_listeners_from_config();

  std::promise<ua::VoidResult> started;
  auto startedFuture = started.get_future();
  server->start_async([&started](ua::VoidResult result) { started.set_value(std::move(result)); });

  ASSERT_EQ(startedFuture.wait_for(30s), std::future_status::ready)
    << "the DEFAULT single-threaded configuration must not hang: create() puts its substituted "
       "certificate store on the server's own executor, so the old blocking fetch deadlocked the "
       "one worker with no timeout and no error";
  workerIsJoinable = true;
  static_cast<void>(startedFuture.get());  // good or bad, but ANSWERED

  shutdown(*server);
}
}  // namespace

// ---------------------------------------------------------------------------
// Found by the integration matrix (2026-10-02): a server whose own certificate violates a served
// endpoint's SecurityPolicy does not start (Bad_ConfigurationError, OPC 10000-6 6.2.2 Table 43 key
// length), and the refusal names the endpoint as the application configured it - its
// ServerEndpointConfig::name - so the operator can find it. An unnamed endpoint is named by its
// SecurityPolicyUri and MessageSecurityMode.
// ---------------------------------------------------------------------------

namespace
{

// Starts a server with one Basic256Sha256 endpoint (`name`, `mode`) whose own certificate is an RSA-1024
// leaf - below the policy's 2048-bit minimum - and returns the start result. With `listAnswer`, the store
// answers the application certificate list with it instead.
ua::VoidResult start_with_a_weak_own_certificate(const std::string& name, ua::MessageSecurityMode mode,
  std::optional<CertificateStore::ApplicationCertificateListResult> listAnswer = std::nullopt)
{
  boost::asio::thread_pool pool{2};
  auto crypto = ua::create_default_crypto([]() { return ua::SecureString{"password"}; });
  ua::TestPki pki{crypto};
  auto rootKeys = ua::test_keys::key_pair(*crypto, ua::test_keys::KeyType::Rsa2048, 90);
  auto root = pki.create_root_ca(rootKeys, "Startup Root", "9001");
  auto weakKeys = ua::test_keys::key_pair(*crypto, ua::test_keys::KeyType::Rsa1024, 0);
  const auto now = ua::DateTime::now();
  auto weakLeaf = pki.create_leaf_cert(weakKeys,
    rootKeys,
    root,
    now,
    ua::DateTime{now.value() + std::chrono::days{365}},
    {"urn:test:server"},
    {"localhost"},
    "Startup Weak Own");

  auto store = ua::test_helpers::FakeCertificateStore::create();
  store->applicationCertificate.certificateType = CertificateType::RsaSha256Application;
  store->applicationCertificate.certificate = weakLeaf;
  store->applicationCertificate.keys = weakKeys;
  store->applicationCertificate.issuerCertificates = {root};
  store->getApplicationCertificatesResult = std::move(listAnswer);

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  ::ua::server::ServerConfig sc;
  {
    ::ua::server::ServerConfig::ListenerConfig listener;
    listener.name = "StartupRefusalListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:0";
    ua::server::ServerEndpointConfig endpoint;
    endpoint.name = name;
    endpoint.messageSecurityMode = mode;
    endpoint.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    endpoint.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(endpoint));
    sc.listeners().push_back(std::move(listener));
  }
  // ServerConfig::validate (which ua::Server runs) refuses an unnamed endpoint; the unnamed case
  // reaches ServerImpl only when it is built without that validation.
  if (!name.empty())
  {
    sc.validate();
  }
  frozen.server = std::move(sc);

  auto server = ServerImpl::create(pool.get_executor(),
    std::move(frozen),
    ua::server::ServerComponents{.crypto = crypto, .applicationGroupCertificateStore = store});
  ua::test_helpers::ServerImplTestAccess{*server}.initialise_listeners_from_config();

  std::promise<ua::VoidResult> started;
  auto startedFuture = started.get_future();
  server->start_async([&started](ua::VoidResult result) { started.set_value(std::move(result)); });
  EXPECT_EQ(startedFuture.wait_for(30s), std::future_status::ready) << "start never completed";
  auto result = startedFuture.get();
  if (result.is_good())
  {
    shutdown(*server);
  }
  server.reset();
  ::ua::test_utils::drain_with_timeout(pool);
  return result;
}

std::string refusal_text(const ua::VoidResult& result)
{
  return result.shared_detail() ? ua::to_string(*result.shared_detail()) : std::string{};
}

}  // namespace

// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-142-STARTUP-REFUSAL-NAMES-THE-ENDPOINT, scope=function)
TEST(ServerStartOwnCertificateRefusal, TheRefusalNamesTheEndpointByItsConfiguredName)
{
  const auto result =
    start_with_a_weak_own_certificate("Plant Floor Secured Endpoint", ua::MessageSecurityMode::Sign);
  ASSERT_EQ(result.status_code().as_status(), ua::Status::BadConfigurationError);
  EXPECT_NE(refusal_text(result).find("Plant Floor Secured Endpoint"), std::string::npos)
    << refusal_text(result);
}

// Control: the same refusal for an endpoint with another name carries that name, not the first - the name
// comes from the configuration, not from the policy.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-142-STARTUP-REFUSAL-NAMES-THE-ENDPOINT, scope=function)
TEST(ServerStartOwnCertificateRefusal, AnotherEndpointNameIsTheOneTheRefusalCarries)
{
  const auto result = start_with_a_weak_own_certificate("Second Endpoint", ua::MessageSecurityMode::Sign);
  ASSERT_EQ(result.status_code().as_status(), ua::Status::BadConfigurationError);
  EXPECT_NE(refusal_text(result).find("Second Endpoint"), std::string::npos) << refusal_text(result);
  EXPECT_EQ(refusal_text(result).find("Plant Floor Secured Endpoint"), std::string::npos);
}

// The server starts only on certificates the store answered Good. An Uncertain answer is refused: the start
// completes with Bad_InternalError (CertificateStoreError, whose cause is the CertificateStoreAnswerUncertain
// refusal carrying the store's code), never with the Uncertain code, and the server does not start.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServerStartOwnCertificateRefusal, AnUncertainCertificateStoreAnswerIsRefused)
{
  const auto result = start_with_a_weak_own_certificate("Uncertain Store Endpoint",
    ua::MessageSecurityMode::Sign,
    CertificateStore::ApplicationCertificateListResult{ua::StatusCode{ua::Status::UncertainLastUsableValue}});
  ASSERT_EQ(result.status_code().as_status(), ua::Status::BadInternalError) << refusal_text(result);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "CertificateStoreError");
  ASSERT_NE(result.shared_detail()->cause, nullptr) << refusal_text(result);
  EXPECT_EQ(result.shared_detail()->cause->code, "CertificateStoreAnswerUncertain");
  EXPECT_EQ(
    result.shared_detail()->cause->innerStatus, ua::StatusCode{ua::Status::UncertainLastUsableValue}.value());
}
