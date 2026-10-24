// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// End-to-end integration tests for the LDS registration feature.
//
// These exercise the REAL outbound driver (ua::app::DiscoveryRegistration driven by a
// ua::app::ClientLdsRegistrar over a live ua::client::Client) against a REAL server-as-LDS
// (ua::server::Server with ServerConfig::LocalDiscoveryServer.enabled=true). Registration
// flows over a live TCP secure channel; the registration is observed via the LDS's session-less
// FindServers aggregation. Short cadence/expiry values are used so the suite stays fast.
//
// Requirement coverage (CTT-mirror rows close at the bottom of the file):
//   SVR-DISC-LDS-001/002/004/005, SVR-DISC-RS-001/003/021, SVR-DISC-RS2-001/003, SVR-DISC-RS-007/009.
//
// Scenarios:
//   1. Happy path        - Server B registers into LDS A over a secured channel; B appears ONLINE.
//   2. Timed re-register - the registration stays present across more than one cadence cycle.
//   3. Backoff when down - an unreachable target backs off, does not crash, fires on_registration_failed.
//   4. Shutdown deregister- stop_async sends a final isOnline=false; B is evicted from FindServers.
//   5. Validation         - None-mode channel and serverUri!=cert applicationUri are REJECTED.
//   6. Mirror_* CTT mirrors for the in-scope DISC-* rows.
//
// Threading discipline: every .get()/wait_for happens on the MAIN test thread only. Pools are
// shut down explicitly via the ComplianceSecured TearDown.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <random>
#include <memory>
#include <string>
#include <vector>

#include "compliance_helpers.h"
#include "matchers.h"

#include "ua_discovery_registration.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_lds_registrar.h"
#include "ua_register_server2_request.h"
#include "ua_register_server2_response.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_registered_server.h"
#include "ua_status.h"

#include "test_components.h"
using namespace std::chrono_literals;

namespace ua::test::integration::discovery::lds
{
namespace
{

using ua::app::ClientLdsRegistrar;
using ua::app::DiscoveryRegistration;
using ua::app::DiscoveryRegistrationConfig;
using ua::app::DiscoveryRegistrationInfo;
using ua::app::DiscoveryRegistrationObserver;
using ua::app::DiscoveryTarget;

// The applicationUri carried by the ComplianceSecured client certificate SAN. The LDS validates
// that the registering server's serverUri equals the peer cert applicationUri (Part 4 section 5.4.5.1),
// so the registered serverUri MUST equal this value for an authenticated registration to be
// accepted.
constexpr std::string_view clientCertUri = "urn:test:compliance:client";

// ---------------------------------------------------------------------------
// RecordingObserver - captures observer edges for the failure-path assertions.
// ---------------------------------------------------------------------------
class RecordingObserver : public DiscoveryRegistrationObserver
{
public:
  void on_registration_established(const DiscoveryRegistrationInfo&) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mEstablished;
  }

  void on_registration_failed(const DiscoveryRegistrationInfo&, ua::StatusCode status,
    std::shared_ptr<const ua::ErrorDetail> detail, std::chrono::steady_clock::time_point) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mFailed;
    mLastFailedStatus = status;
    mLastFailedDetail = std::move(detail);
  }

  void on_registration_deregistered(const DiscoveryRegistrationInfo&) override
  {
    std::lock_guard<std::mutex> lock(mMutex);
    ++mDeregistered;
  }

  int established() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mEstablished;
  }

  int failed() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mFailed;
  }

  int deregistered() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mDeregistered;
  }

  ua::StatusCode last_failed_status() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastFailedStatus;
  }

  std::shared_ptr<const ua::ErrorDetail> last_failed_detail() const
  {
    std::lock_guard<std::mutex> lock(mMutex);
    return mLastFailedDetail;
  }

private:
  mutable std::mutex mMutex;
  int mEstablished{0};
  int mFailed{0};
  int mDeregistered{0};
  ua::StatusCode mLastFailedStatus{};
  std::shared_ptr<const ua::ErrorDetail> mLastFailedDetail;
};

// ===========================================================================
// Fixture: a secured server acting as an LDS, plus a shared client for the
// outbound registration driver. The server trusts the client cert (inherited
// from ComplianceSecured), so an authenticated registration with
// serverUri == clientCertUri is accepted.
// ===========================================================================
class LdsRegistrationTest : public ComplianceSecured
{
protected:
  // Turn the served server into a Local Discovery Server with a short online-registration
  // expiry so eviction/timeout behaviour is observable within the test budget.
  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.localDiscoveryServer.enabled = true;
    cfg.server.localDiscoveryServer.registrationExpiry = 5s;
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    // A shared Client reusing the fixture crypto + client cert store (so its app-instance cert
    // SAN URI is clientCertUri and it trusts the server cert). This client backs the registrar.
    auto clientAppConfig = ua::test_utils::create_test_config();
    clientAppConfig.application_description_part().applicationUri = std::string{clientCertUri};
    client::CreateConfig clientCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppConfig)};
    mRegistrarClient = std::make_shared<CoreClient>(CoreClient::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto, .applicationGroupCertificateStore = mClientCertStore}));
    mRegistrar = std::make_shared<ClientLdsRegistrar>(mRegistrarClient);
  }

  void TearDown() override
  {
    if (mDriver)
    {
      std::promise<void> done;
      mDriver->stop_async([&done](ua::VoidResult) { done.set_value(); });
      done.get_future().wait_for(8s);
      mDriver.reset();
    }
    if (mRegistrarClient)
    {
      std::promise<void> done;
      mRegistrarClient->shutdown_async([&done](ua::VoidResult) { done.set_value(); });
      done.get_future().wait_for(5s);
    }
    mRegistrar.reset();
    mRegistrarClient.reset();
    ComplianceSecured::TearDown();
  }

  // Build a RegisteredServer record whose serverUri matches the client cert SAN (so the LDS
  // accepts the authenticated registration).
  ua::RegisteredServer make_identity(const std::string& serverUri = std::string{clientCertUri})
  {
    ua::RegisteredServer server;
    server.server_uri() = ua::String{serverUri};
    server.product_uri() = ua::String{"urn:test:product"};
    server.server_type() = ua::ApplicationType::Server;
    server.server_names().payload().push_back(
      ua::LocalizedText{ua::String{"en"}, ua::String{"Registering Server B"}});
    server.discovery_urls().payload().push_back(ua::String{"opc.tcp://server-b:4840"});
    server.is_online() = true;
    return server;
  }

  // A secured (Basic256Sha256 / SignAndEncrypt) target pointing at the LDS endpoint.
  DiscoveryTarget secured_target()
  {
    DiscoveryTarget target;
    target.discoveryUrl = mEndpointUrl;
    target.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    target.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    return target;
  }

  DiscoveryRegistrationConfig short_config(std::vector<DiscoveryTarget> targets)
  {
    DiscoveryRegistrationConfig cfg;
    cfg.targets = std::move(targets);
    cfg.cadence = 1s;
    cfg.backoffInitial = 1s;
    cfg.backoffCap = 4s;
    cfg.shutdownDeregisterTimeout = 3s;
    return cfg;
  }

  void start_driver(DiscoveryRegistrationConfig cfg, ua::RegisteredServer identity)
  {
    mDriver = DiscoveryRegistration::create(
      mServerThreadPool.executor(), mRegistrar, std::move(identity), std::move(cfg));
    std::promise<void> started;
    mDriver->start_async([&started](ua::VoidResult) { started.set_value(); });
    ASSERT_EQ(started.get_future().wait_for(2s), std::future_status::ready);
  }

  // Query the LDS via a fresh session-less None channel and return the FindServers servers list.
  std::vector<std::string> find_server_uris()
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    FindServersRequest req;
    req.endpoint_url() = mEndpointUrl;
    auto resp = channel.find_servers_sync(std::move(req));
    EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
    std::vector<std::string> uris;
    for (const auto& app : resp.servers())
      uris.push_back(std::string{app.application_uri()});
    channel.close_sync();
    return uris;
  }

  bool lds_lists(const std::string& serverUri)
  {
    auto uris = find_server_uris();
    return std::find(uris.begin(), uris.end(), serverUri) != uris.end();
  }

  template<typename Pred>
  bool poll_until(Pred pred, std::chrono::milliseconds budget)
  {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (pred())
        return true;
      std::this_thread::sleep_for(50ms);
    }
    return pred();
  }

  std::shared_ptr<CoreClient> mRegistrarClient;
  std::shared_ptr<ClientLdsRegistrar> mRegistrar;
  std::shared_ptr<DiscoveryRegistration> mDriver;
};

// ===========================================================================
// 1. Happy path - Server B registers into LDS A and appears ONLINE.
// ===========================================================================
// SVR-DISC-LDS-001/002/004, SVR-DISC-RS-001/021, SVR-DISC-RS2-001. The registration travels over a live,
// authenticated (SignAndEncrypt) secure channel to the LDS, lands in the registry, and surfaces
// in the LDS's session-less FindServers aggregation. This is the discriminating end-to-end proof:
// the URI is absent before registration and present after, observed through a SEPARATE channel.
TEST_F(LdsRegistrationTest, RegisteredServerAppearsOnlineInFindServers)
{
  const std::string serverUri{clientCertUri};
  ASSERT_FALSE(lds_lists(serverUri)) << "the registering server must not be listed before it registers";

  start_driver(short_config({secured_target()}), make_identity(serverUri));

  EXPECT_TRUE(poll_until([&] { return lds_lists(serverUri); }, 6000ms))
    << "the registered server must surface ONLINE in the LDS FindServers result";
}

// ===========================================================================
// 2. Timed re-register - registration is refreshed across cadence cycles.
// ===========================================================================
// SVR-DISC-RS-007. The LDS online-registration expiry is 5s; cadence is 1s. If the driver did not
// re-register, the entry would expire and disappear. Asserting presence well beyond the expiry
// window proves the periodic re-registration keeps the entry alive.
TEST_F(LdsRegistrationTest, RegistrationRefreshedAcrossCadenceCyclesBeyondExpiry)
{
  const std::string serverUri{clientCertUri};
  start_driver(short_config({secured_target()}), make_identity(serverUri));

  ASSERT_TRUE(poll_until([&] { return lds_lists(serverUri); }, 6000ms)) << "initial registration must land";

  // Wait beyond the 5s registrationExpiry; re-registration must keep the entry present.
  std::this_thread::sleep_for(7s);
  EXPECT_TRUE(lds_lists(serverUri))
    << "periodic re-registration must keep the entry alive past the LDS expiry window";
}

// ===========================================================================
// 3. Backoff when the LDS is unreachable - driver retries, does not crash, observes failure.
// ===========================================================================
// SVR-DISC-RS-001 (must use a SecureChannel) / SVR-DISC-RS-011-class retry. Pointing the driver at a dead
// port surfaces a channel-open failure on every cycle. The driver must keep running (no crash) and
// the failure must reach the observer with a populated ErrorDetail.
TEST_F(LdsRegistrationTest, UnreachableLdsBacksOffAndReportsFailureWithErrorDetail)
{
  DiscoveryTarget dead;
  // 127.0.0.1:1 is reserved/unbound - connection is refused promptly.
  dead.discoveryUrl = "opc.tcp://127.0.0.1:1";
  dead.messageSecurityMode = MessageSecurityMode::None;

  auto observer = std::make_shared<RecordingObserver>();
  mDriver = DiscoveryRegistration::create(
    mServerThreadPool.executor(), mRegistrar, make_identity(), short_config({dead}));
  mDriver->set_observer(observer);
  std::promise<void> started;
  mDriver->start_async([&started](ua::VoidResult) { started.set_value(); });
  ASSERT_EQ(started.get_future().wait_for(2s), std::future_status::ready);

  ASSERT_TRUE(poll_until([&] { return observer->failed() >= 1; }, 6000ms))
    << "an unreachable LDS must raise the on_registration_failed observer edge";
  EXPECT_TRUE(observer->last_failed_status().is_bad());
  ASSERT_NE(observer->last_failed_detail(), nullptr)
    << "the failure must carry an ErrorDetail (never silently discarded)";

  // The driver keeps retrying without crashing: more failures accumulate.
  EXPECT_TRUE(poll_until([&] { return observer->failed() >= 2; }, 6000ms))
    << "the driver must keep retrying after backoff, not give up or crash";
}

// ===========================================================================
// 3b. The target's security default (public API review item 9, API-9.3, D9).
// ===========================================================================
// A target that names only its URL registers SignAndEncrypt with the strongest policy the LDS offers,
// so it registers with a conformant discovery server out of the box; None is used only when set, and the
// SDK's own LDS refuses it (Part 4 5.4.5.1); a mode and policy that contradict each other are refused
// before any channel is opened.
TEST_F(LdsRegistrationTest, ATargetNamingOnlyItsUrlRegistersWithTheSdksOwnLds)
{
  const std::string serverUri{clientCertUri};
  ASSERT_FALSE(lds_lists(serverUri)) << "the registering server must not be listed before it registers";

  start_driver(short_config({DiscoveryTarget{.discoveryUrl = mEndpointUrl}}), make_identity(serverUri));

  EXPECT_TRUE(poll_until([&] { return lds_lists(serverUri); }, 6000ms))
    << "a default target must register: SignAndEncrypt with the strongest policy the LDS offers";
}

TEST_F(LdsRegistrationTest, AnExplicitNoneTargetIsRefusedBySecurityModeInsufficient)
{
  auto observer = std::make_shared<RecordingObserver>();
  mDriver = DiscoveryRegistration::create(mServerThreadPool.executor(),
    mRegistrar,
    make_identity(),
    short_config(
      {DiscoveryTarget{.discoveryUrl = mEndpointUrl, .messageSecurityMode = MessageSecurityMode::None}}));
  mDriver->set_observer(observer);
  std::promise<void> started;
  mDriver->start_async([&started](ua::VoidResult) { started.set_value(); });
  ASSERT_EQ(started.get_future().wait_for(2s), std::future_status::ready);

  ASSERT_TRUE(poll_until([&] { return observer->failed() >= 1; }, 6000ms))
    << "a None registration channel must fail at a conformant LDS";
  EXPECT_EQ(observer->last_failed_status().as_status(), Status::BadSecurityModeInsufficient);
  EXPECT_EQ(observer->established(), 0);
}

TEST_F(LdsRegistrationTest, AContradictoryTargetIsRefusedBeforeAnyChannel)
{
  auto observer = std::make_shared<RecordingObserver>();
  mDriver = DiscoveryRegistration::create(mServerThreadPool.executor(),
    mRegistrar,
    make_identity(),
    short_config({DiscoveryTarget{.discoveryUrl = mEndpointUrl,
      .messageSecurityMode = MessageSecurityMode::None,
      .securityPolicyId = SecurityPolicyId::Basic256Sha256}}));
  mDriver->set_observer(observer);
  std::promise<void> started;
  mDriver->start_async([&started](ua::VoidResult) { started.set_value(); });
  ASSERT_EQ(started.get_future().wait_for(2s), std::future_status::ready);

  ASSERT_TRUE(poll_until([&] { return observer->failed() >= 1; }, 6000ms));
  EXPECT_EQ(observer->last_failed_status().as_status(), Status::BadInvalidArgument);
  ASSERT_NE(observer->last_failed_detail(), nullptr);
  EXPECT_EQ(observer->last_failed_detail()->code, "DiscoveryTargetSecurityMismatch")
    << "None with a secured policy is refused, never corrected to one or the other";
}

// ===========================================================================
// 4. Shutdown deregister - a final isOnline=false evicts the entry from the LDS.
// ===========================================================================
// SVR-DISC-RS-009. stop_async sends exactly one final register with isOnline=false; the LDS evicts an
// offline registration immediately, so the entry disappears from FindServers after shutdown.
TEST_F(LdsRegistrationTest, ShutdownDeregisterEvictsFromFindServers)
{
  const std::string serverUri{clientCertUri};
  start_driver(short_config({secured_target()}), make_identity(serverUri));

  ASSERT_TRUE(poll_until([&] { return lds_lists(serverUri); }, 6000ms)) << "registration must land first";

  std::promise<void> stopped;
  mDriver->stop_async([&stopped](ua::VoidResult) { stopped.set_value(); });
  ASSERT_EQ(stopped.get_future().wait_for(5s), std::future_status::ready) << "stop_async must complete";
  mDriver.reset();  // already stopped; avoid a second stop in TearDown

  // The final isOnline=false deregister evicts the entry; the cadence is stopped, so once gone it
  // stays gone.
  EXPECT_TRUE(poll_until([&] { return !lds_lists(serverUri); }, 4000ms))
    << "the bounded shutdown deregister must evict the server from the LDS";
}

// ===========================================================================
// 5. Validation negatives (driven through the real channel + LDS handler).
// ===========================================================================

// SVR-DISC-LDS-005 / SVR-DISC-RS-001. A RegisterServer2 over a None-mode (unauthenticated) channel is
// rejected by the LDS with Bad_SecurityModeInsufficient.
TEST_F(LdsRegistrationTest, Mirror_DISC_LDS_005_NoneModeChannelRejected)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});  // None/None
  RegisterServer2Request req;
  req.server() = make_identity();  // serverUri matches cert, but the channel is unauthenticated

  // The LDS rejects this with a ServiceFault, so use the non-throwing variant and assert the
  // returned Result status (the throwing *_sync would throw UaException before any assertion).
  auto result = channel.try_register_server2_sync(std::move(req));
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadSecurityModeInsufficient);
  channel.close_sync();
}

// SVR-DISC-RS-003 / SVR-DISC-LDS-005. A registration whose serverUri does not match the peer certificate
// applicationUri is rejected with Bad_ServerUriInvalid even over a secured channel.
TEST_F(LdsRegistrationTest, Mirror_DISC_RS_003_ServerUriMismatchRejected)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = mServerCert});
  RegisterServer2Request req;
  req.server() = make_identity("urn:server:does-not-match-cert");  // mismatched serverUri

  // Rejected with a ServiceFault - assert via the non-throwing variant's Result status.
  auto result = channel.try_register_server2_sync(std::move(req));
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadServerUriInvalid);
  channel.close_sync();
}

// ===========================================================================
// 6. CTT Mirror_* tests for the in-scope DISC-* rows.
// ===========================================================================

// SVR-DISC-LDS-004 / SVR-DISC-RS-001. Session-less RegisterServer2 over an authenticated channel succeeds
// and the server becomes discoverable through FindServers (register -> FindServers roundtrip).
TEST_F(LdsRegistrationTest, Mirror_DISC_LDS_004_SessionlessRegisterServer2RoundtripsToFindServers)
{
  const std::string serverUri{clientCertUri};
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = mServerCert});

  RegisterServer2Request req;
  req.server() = make_identity(serverUri);
  auto resp = channel.register_server2_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  channel.close_sync();

  EXPECT_TRUE(lds_lists(serverUri)) << "a session-less RegisterServer2 must surface in FindServers";
}

// SVR-DISC-LDS-004. The v1 RegisterServer surface is equally session-less and lands in the registry.
TEST_F(LdsRegistrationTest, Mirror_DISC_LDS_004_SessionlessRegisterServerV1RoundtripsToFindServers)
{
  const std::string serverUri{clientCertUri};
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = mServerCert});

  RegisterServerRequest req;
  req.server() = make_identity(serverUri);
  auto resp = channel.register_server_sync(std::move(req));
  EXPECT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  channel.close_sync();

  EXPECT_TRUE(lds_lists(serverUri)) << "a session-less RegisterServer (v1) must surface in FindServers";
}

// SVR-DISC-RS2-003 / SVR-DISC-RS-028. The RegisterServer2 response carries one configurationResult per
// discoveryConfiguration entry submitted.
TEST_F(LdsRegistrationTest, Mirror_DISC_RS2_003_RegisterServer2ReturnsPerConfigResults)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = mServerCert});

  RegisterServer2Request req;
  req.server() = make_identity();
  // Two discovery-configuration entries -> expect two configurationResults.
  {
    ua::RefStructure<ua::Structure> entry1;
    entry1 = std::unique_ptr<ua::Structure>{std::make_unique<ua::RegisteredServer>()};
    ua::RefStructure<ua::Structure> entry2;
    entry2 = std::unique_ptr<ua::Structure>{std::make_unique<ua::RegisteredServer>()};
    req.discovery_configuration().payload().push_back(std::move(entry1));
    req.discovery_configuration().payload().push_back(std::move(entry2));
  }

  auto resp = channel.register_server2_sync(std::move(req));
  ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_EQ(resp.configuration_results().payload().size(), 2u)
    << "one StatusCode per discoveryConfiguration entry";
  channel.close_sync();
}

// SVR-DISC-RS-021 / SVR-DISC-RS-009. isOnline lifecycle through the real handler: an online registration
// surfaces in FindServers, and a subsequent isOnline=false registration evicts it.
TEST_F(LdsRegistrationTest, Mirror_DISC_RS_021_IsOnlineLifecycleAppearsThenEvicts)
{
  const std::string serverUri{clientCertUri};
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
    .securityMode = MessageSecurityMode::SignAndEncrypt,
    .securityPolicyId = SecurityPolicyId::Basic256Sha256,
    .serverCertificate = mServerCert});

  // Online -> present.
  {
    RegisterServer2Request req;
    req.server() = make_identity(serverUri);
    auto resp = channel.register_server2_sync(std::move(req));
    ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  }
  EXPECT_TRUE(lds_lists(serverUri)) << "online registration must appear in FindServers";

  // Offline -> evicted immediately.
  {
    auto identity = make_identity(serverUri);
    identity.is_online() = false;
    RegisterServer2Request req;
    req.server() = std::move(identity);
    auto resp = channel.register_server2_sync(std::move(req));
    ASSERT_THAT(resp, ::ua::test_helpers::ServiceResultIsGood());
  }
  EXPECT_FALSE(lds_lists(serverUri)) << "an isOnline=false registration must evict the entry";
  channel.close_sync();
}

// ===========================================================================
// 7. Semaphore files confined to the configured directory.
// ===========================================================================

/// The LDS with `LocalDiscoveryServer::semaphoreFileDirectory` set to a directory of the test's own.
class LdsSemaphoreDirectoryTest : public LdsRegistrationTest
{
protected:
  LdsSemaphoreDirectoryTest()
    : mDirectory{std::filesystem::temp_directory_path() /
                 ("uasdk-lds-it-semaphores-" + std::to_string(std::random_device{}()))}
  {
    std::filesystem::create_directories(mDirectory);
  }

  ~LdsSemaphoreDirectoryTest() override
  {
    std::error_code ignored;
    std::filesystem::remove_all(mDirectory, ignored);
  }

  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    LdsRegistrationTest::configure_server_create_config(cfg);
    cfg.server.localDiscoveryServer.semaphoreFileDirectory = mDirectory.string();
  }

  /// RegisterServer2 over the authenticated channel, naming @p semaphoreFile.
  auto register_with_semaphore(const std::filesystem::path& semaphoreFile)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl,
      .securityMode = MessageSecurityMode::SignAndEncrypt,
      .securityPolicyId = SecurityPolicyId::Basic256Sha256,
      .serverCertificate = mServerCert});
    RegisterServer2Request req;
    req.server() = make_identity();
    req.server().semaphore_file_path() = ua::String{semaphoreFile.string()};
    auto result = channel.try_register_server2_sync(std::move(req));
    channel.close_sync();
    return result;
  }

  std::filesystem::path mDirectory;
};

// Part 4 5.4.5.2 / SVC-15. With a semaphore directory configured, a RegisterServer2 naming a semaphore
// file outside it is refused with Bad_SemaphoreFileMissing and nothing is registered, although the file
// exists; one naming an existing file inside it is honoured and surfaces in FindServers. Falsifiable: an
// LDS that ignores the directory registers the first request too.
// @verifies AC-SVR-DISC-RS-019-SEMAPHORE-FILE-PATH-IS-CONFINED-TO-THE-CONFIGURED-DIRECTORY
TEST_F(LdsSemaphoreDirectoryTest, ASemaphoreFileOutsideTheDirectoryIsRefusedAndOneInsideIsHonoured)
{
  const std::string serverUri{clientCertUri};
  const auto outside = mDirectory.parent_path() / (mDirectory.filename().string() + "-outside.sem");
  {
    std::ofstream file{outside.string()};
    file << "present";
  }
  auto refused = register_with_semaphore(outside);
  std::error_code ignored;
  std::filesystem::remove(outside, ignored);
  ASSERT_TRUE(refused.is_bad()) << "a semaphore file outside the configured directory must be refused";
  EXPECT_EQ(refused.status_code().as_status(), Status::BadSemaphoreFileMissing);
  EXPECT_FALSE(lds_lists(serverUri)) << "a refused registration is not stored";

  const auto inside = mDirectory / "inside.sem";
  {
    std::ofstream file{inside.string()};
    file << "present";
  }
  auto honoured = register_with_semaphore(inside);
  ASSERT_TRUE(honoured.is_good()) << "a semaphore file inside the configured directory must be honoured";
  EXPECT_THAT(honoured.value(), ::ua::test_helpers::ServiceResultIsGood());
  EXPECT_TRUE(lds_lists(serverUri)) << "the honoured registration must surface in FindServers";
}

}  // namespace
}  // namespace ua::test::integration::discovery::lds
