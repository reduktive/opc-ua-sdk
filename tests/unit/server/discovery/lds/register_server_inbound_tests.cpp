// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the inbound, session-LESS RegisterServer / RegisterServer2 dispatch and
// validation path through ua::server::DiscoveryServiceSet, plus the FindServers aggregation
// of the server-as-LDS registry.
//
// Requirement coverage:
//   SVR-DISC-LDS-004 - All Applications / LDS SHALL accept RegisterServer2 + RegisterServer (inbound).
//   SVR-DISC-LDS-005 - LDS rejects an unauthenticated channel / serverUri != cert applicationUri.
//   SVR-DISC-RS-003  - Discovery Server SHALL reject if serverUri != cert applicationUri.
//   SVR-DISC-RS2-003 - RegisterServer2 response carries per-config configurationResults[].
//   SVR-DISC-LDS-001 - RegisterServer is part of the LDS surface (feature gate when OFF).
//   SVR-DISC-LDS-002 / SVR-DISC-RS-021 - FindServers returns self + known online Servers, no Session info.
//
// The DISCRIMINATING property: DiscoveryServiceSet::create() routes a decoded RegisterServer2 /
// RegisterServer request to the handler with ONLY a weak DiscoveryDependencies + an
// InboundRegistrationContext - there is NO Session parameter anywhere in the signature or the
// flow. A session-routed implementation could not satisfy this call shape, and the registration
// still lands in the store. That is exactly the session-less inbound dispatch the spec requires.
//
// Stimulus flows through the real production code path (DiscoveryServiceSet<RequestType>) - the
// same template the secure-channel dispatch table instantiates. All blocking happens on the main
// test thread; the pool is shut down explicitly in TearDown.

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/thread_pool.hpp>

#include "ua_error_detail.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_register_server2_request.h"
#include "ua_register_server2_response.h"
#include "ua_register_server_request.h"
#include "ua_register_server_response.h"
#include "ua_registered_server.h"
#include "ua_registered_server_store.h"
#include "ua_server_configuration.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_service_fault.h"
#include "ua_transport_address.h"

#include "fake_discovery_dependencies.h"
#include "fake_certificate_store.h"
#include "ua_discovery_service_set.h"

using namespace std::chrono_literals;

namespace ua::test::server::discovery::lds
{
namespace
{

using ua::server::DiscoveryServiceSet;
using ua::server::InboundRegistrationContext;
using ua::server::RegisteredServerStore;
using Config = ua::server::ServerConfig::LocalDiscoveryServer;

ua::RegisteredServer make_registered_server(const std::string& serverUri, bool online = true)
{
  ua::RegisteredServer server;
  server.server_uri() = ua::String{serverUri};
  server.product_uri() = ua::String{"urn:test:product"};
  server.server_type() = ua::ApplicationType::Server;
  server.server_names().payload().push_back(ua::LocalizedText{ua::String{"en"}, ua::String{"Test Server"}});
  server.discovery_urls().payload().push_back(ua::String{"opc.tcp://localhost:4840"});
  server.is_online() = online;
  return server;
}

class RegisterServerInboundTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mPool = std::make_unique<boost::asio::thread_pool>(/*noOfThreads=*/1);
    mCertStore = ua::test_helpers::FakeCertificateStore::create();
    mDeps = std::make_shared<ua::test_helpers::FakeDiscoveryDependencies>(mPool->executor());
    mDeps->set_default_application_group_certificate_store(mCertStore);
  }

  void TearDown() override
  {
    if (mStore)
    {
      std::promise<void> done;
      mStore->shutdown_async([&done](ua::VoidResult) { done.set_value(); });
      done.get_future().wait_for(2s);
    }
    mDeps.reset();
    mStore.reset();
    mCertStore.reset();
    if (mPool)
    {
      mPool->stop();
      mPool->join();
    }
  }

  // Enable the server-as-LDS feature by installing a live store.
  void enable_lds(Config config = Config{.enabled = true, .registrationExpiry = 600s})
  {
    mStore = RegisteredServerStore::create(mPool->executor(), config);
    mDeps->set_registered_server_store(mStore);
  }

  // Drive a RegisterServer2 request through the real session-less DiscoveryServiceSet path with
  // the supplied channel context. Returns the wire response; blocks on the main test thread only.
  ua::Response run_register2(ua::RegisterServer2Request&& request, InboundRegistrationContext ctx)
  {
    std::promise<ua::Response> p;
    auto fut = p.get_future();
    auto service = DiscoveryServiceSet<ua::RegisterServer2Request>::create(
      mDeps,
      ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(request),
      mPool->executor(),
      [&p](ua::Response r) { p.set_value(std::move(r)); },
      std::move(ctx));
    EXPECT_EQ(fut.wait_for(2s), std::future_status::ready) << "RegisterServer2 callback did not fire";
    return fut.get();
  }

  ua::Response run_register1(ua::RegisterServerRequest&& request, InboundRegistrationContext ctx)
  {
    std::promise<ua::Response> p;
    auto fut = p.get_future();
    auto service = DiscoveryServiceSet<ua::RegisterServerRequest>::create(
      mDeps,
      ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(request),
      mPool->executor(),
      [&p](ua::Response r) { p.set_value(std::move(r)); },
      std::move(ctx));
    EXPECT_EQ(fut.wait_for(2s), std::future_status::ready) << "RegisterServer callback did not fire";
    return fut.get();
  }

  std::unique_ptr<boost::asio::thread_pool> mPool;
  std::shared_ptr<ua::test_helpers::FakeCertificateStore> mCertStore;
  std::shared_ptr<ua::test_helpers::FakeDiscoveryDependencies> mDeps;
  std::shared_ptr<RegisteredServerStore> mStore;
};

// =============================================================================================
// DISCRIMINATING test - session-less RegisterServer2 reaches the handler and lands in the store.
// =============================================================================================
//
// SVR-DISC-LDS-004 / SVR-DISC-LDS-005. The request flows through DiscoveryServiceSet with NO session, only
// an InboundRegistrationContext describing the channel. A session-routed implementation could not
// be exercised by this call shape. We assert both the wire success AND the side effect in the
// store (the registration is observable in snapshot()).
TEST_F(RegisterServerInboundTest, SessionlessRegisterServer2LandsInStore)
{
  enable_lds();

  const std::string serverUri = "urn:server:a";
  ua::RegisterServer2Request req;
  req.server() = make_registered_server(serverUri);

  // Authenticated channel + matching peer cert applicationUri - the only validation inputs, all
  // derived from the channel context, never from a session.
  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  ctx.peerApplicationUri = serverUri;

  auto response = run_register2(std::move(req), ctx);

  auto* registerResponse = dynamic_cast<ua::RegisterServer2Response*>(response.second.get());
  ASSERT_NE(registerResponse, nullptr) << "expected RegisterServer2Response, got ServiceFault";
  EXPECT_EQ(registerResponse->response_header().service_result(), ua::Status::Good);

  // The side effect: the registration is in the store, reachable with no session involved.
  auto snapshot = mStore->snapshot();
  ASSERT_EQ(snapshot.size(), 1u) << "session-less RegisterServer2 must write to the LDS store";
  EXPECT_EQ(std::string{snapshot[0].server_uri()}, serverUri);
}

// SVR-DISC-LDS-004 - the v1 RegisterServer surface is equally session-less and lands in the store.
TEST_F(RegisterServerInboundTest, SessionlessRegisterServerV1LandsInStore)
{
  enable_lds();

  const std::string serverUri = "urn:server:v1";
  ua::RegisterServerRequest req;
  req.server() = make_registered_server(serverUri);

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::Sign;
  ctx.peerApplicationUri = serverUri;

  auto response = run_register1(std::move(req), ctx);

  auto* registerResponse = dynamic_cast<ua::RegisterServerResponse*>(response.second.get());
  ASSERT_NE(registerResponse, nullptr) << "expected RegisterServerResponse, got ServiceFault";
  EXPECT_EQ(registerResponse->response_header().service_result(), ua::Status::Good);

  auto snapshot = mStore->snapshot();
  ASSERT_EQ(snapshot.size(), 1u);
  EXPECT_EQ(std::string{snapshot[0].server_uri()}, serverUri);
}

// SVR-DISC-RS2-003 / SVR-DISC-RS-028 - RegisterServer2 returns one configurationResult per discovery config.
TEST_F(RegisterServerInboundTest, RegisterServer2ReturnsPerConfigResults)
{
  enable_lds();

  const std::string serverUri = "urn:server:a";
  ua::RegisterServer2Request req;
  req.server() = make_registered_server(serverUri);
  // Two discovery-configuration entries -> expect two configurationResults. The handler only
  // counts the entries, so any Structure (here a RegisteredServer) is a valid stand-in.
  {
    ua::RefStructure<ua::Structure> entry1;
    entry1 = std::unique_ptr<ua::Structure>{std::make_unique<ua::RegisteredServer>()};
    ua::RefStructure<ua::Structure> entry2;
    entry2 = std::unique_ptr<ua::Structure>{std::make_unique<ua::RegisteredServer>()};
    req.discovery_configuration().payload().push_back(std::move(entry1));
    req.discovery_configuration().payload().push_back(std::move(entry2));
  }

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  ctx.peerApplicationUri = serverUri;

  auto response = run_register2(std::move(req), ctx);
  auto* registerResponse = dynamic_cast<ua::RegisterServer2Response*>(response.second.get());
  ASSERT_NE(registerResponse, nullptr);
  EXPECT_EQ(registerResponse->configuration_results().payload().size(), 2u)
    << "one StatusCode per discoveryConfiguration entry";
}

// =============================================================================================
// Validation negatives.
// =============================================================================================

// SVR-DISC-LDS-005 - an unauthenticated (None-mode) channel is rejected with the locked status + tag.
TEST_F(RegisterServerInboundTest, NoneModeChannelRejected)
{
  enable_lds();

  ua::RegisterServer2Request req;
  req.server() = make_registered_server("urn:server:a");

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::None;  // unauthenticated
  ctx.peerApplicationUri = "urn:server:a";

  auto response = run_register2(std::move(req), ctx);

  auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "None-mode channel must be rejected with a ServiceFault";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadSecurityModeInsufficient);
  EXPECT_TRUE(mStore->snapshot().empty()) << "rejected registration must not reach the store";
}

// SVR-DISC-RS-003 / SVR-DISC-LDS-005 - serverUri != cert applicationUri is rejected.
TEST_F(RegisterServerInboundTest, ServerUriMismatchRejected)
{
  enable_lds();

  ua::RegisterServer2Request req;
  req.server() = make_registered_server("urn:server:claimed");

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  ctx.peerApplicationUri = "urn:server:actual-cert";  // mismatched against serverUri

  auto response = run_register2(std::move(req), ctx);

  auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "serverUri/cert mismatch must be rejected";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadServerUriInvalid);
  EXPECT_TRUE(mStore->snapshot().empty());
}

// SVR-DISC-LDS-001 - feature OFF (no store): RegisterServer is unsupported (Bad_ServiceUnsupported).
TEST_F(RegisterServerInboundTest, FeatureDisabledReturnsServiceUnsupported)
{
  // Do NOT enable_lds(): the fake returns a null store, modelling the gated-OFF feature.
  ua::RegisterServer2Request req;
  req.server() = make_registered_server("urn:server:a");

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  ctx.peerApplicationUri = "urn:server:a";

  auto response = run_register2(std::move(req), ctx);

  auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "feature OFF must fault with Bad_ServiceUnsupported";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadServiceUnsupported);
}

// SVR-DISC-RS-016 - an empty serverUri is rejected (Bad_ServerUriInvalid). The channel is authenticated
// so this trips the serverUri-non-empty check, not the security-mode or mismatch checks.
TEST_F(RegisterServerInboundTest, EmptyServerUriRejected)
{
  enable_lds();

  ua::RegisterServer2Request req;
  req.server() = make_registered_server("");  // empty serverUri

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  ctx.peerApplicationUri = "urn:server:a";

  auto response = run_register2(std::move(req), ctx);

  auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "empty serverUri must be rejected";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadServerUriInvalid);
  EXPECT_TRUE(mStore->snapshot().empty());
}

// SVR-DISC-RS-017 - empty serverNames is rejected (Bad_ServerNameMissing).
// @verifies AC-SVR-DISC-RS-017-SERVERNAMEMISSING
TEST_F(RegisterServerInboundTest, EmptyServerNamesRejected)
{
  enable_lds();

  auto server = make_registered_server("urn:server:a");
  server.server_names().payload().clear();

  ua::RegisterServer2Request req;
  req.server() = std::move(server);

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  ctx.peerApplicationUri = "urn:server:a";

  auto response = run_register2(std::move(req), ctx);

  auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "empty serverNames must be rejected";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadServerNameMissing);
  EXPECT_TRUE(mStore->snapshot().empty());
}

// SVR-DISC-RS-020 - a Client (non-Server) applicationType is rejected (Bad_InvalidArgument).
TEST_F(RegisterServerInboundTest, ClientApplicationTypeRejected)
{
  enable_lds();

  auto server = make_registered_server("urn:server:a");
  server.server_type() = ua::ApplicationType::Client;

  ua::RegisterServer2Request req;
  req.server() = std::move(server);

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  ctx.peerApplicationUri = "urn:server:a";

  auto response = run_register2(std::move(req), ctx);

  auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "Client applicationType must be rejected";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadInvalidArgument);
  EXPECT_TRUE(mStore->snapshot().empty());
}

// SVR-DISC-RS-018 - an online registration with empty discoveryUrls is rejected (Bad_DiscoveryUrlMissing).
// @verifies AC-SVR-DISC-RS-018-DISCOVERYURLMISSING
TEST_F(RegisterServerInboundTest, OnlineRegistrationWithoutDiscoveryUrlsRejected)
{
  enable_lds();

  auto server = make_registered_server("urn:server:a", /*online=*/true);
  server.discovery_urls().payload().clear();

  ua::RegisterServer2Request req;
  req.server() = std::move(server);

  InboundRegistrationContext ctx;
  ctx.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  ctx.peerApplicationUri = "urn:server:a";

  auto response = run_register2(std::move(req), ctx);

  auto* fault = dynamic_cast<ua::ServiceFault*>(response.second.get());
  ASSERT_NE(fault, nullptr) << "online registration without discoveryUrls must be rejected";
  EXPECT_EQ(fault->response_header().service_result(), ua::Status::BadDiscoveryUrlMissing);
  EXPECT_TRUE(mStore->snapshot().empty());
}

// =============================================================================================
// FindServers aggregation (SVR-DISC-LDS-002 / SVR-DISC-RS-021).
// =============================================================================================

ua::server::ServerEndpointConfig make_none_endpoint(std::string name)
{
  ua::server::ServerEndpointConfig cfg;
  cfg.name = std::move(name);
  cfg.securityPolicyId = ua::SecurityPolicyId::None;
  cfg.messageSecurityMode = ua::MessageSecurityMode::None;
  cfg.transportProfile = ua::TransportProfileId::UaTcpUaScUaBinary;
  return cfg;
}

class FindServersAggregationTest : public RegisterServerInboundTest
{
protected:
  void stage_one_listener()
  {
    mDeps->add_listener(ua::server::ListenerHandle{1},
      {make_none_endpoint("ep1")},
      {ua::transport::EndpointUrl{"opc.tcp://localhost:4840/"}});
  }

  ua::Response run_find_servers(ua::FindServersRequest&& req)
  {
    std::promise<ua::Response> p;
    auto fut = p.get_future();
    auto service = DiscoveryServiceSet<ua::FindServersRequest>::create(mDeps,
      ua::LocaleId{"en"},
      /*requestId=*/0,
      std::move(req),
      mPool->executor(),
      [&p](ua::Response r) { p.set_value(std::move(r)); });
    EXPECT_EQ(fut.wait_for(2s), std::future_status::ready) << "FindServers callback did not fire";
    return fut.get();
  }

  // Insert an online registration directly via the store, blocking on the main thread only.
  void store_registration(const ua::RegisteredServer& server)
  {
    std::promise<ua::VoidResult> p;
    auto fut = p.get_future();
    mStore->register_async(
      ua::RegisteredServer{server}, [&p](ua::VoidResult r) { p.set_value(std::move(r)); });
    ASSERT_EQ(fut.wait_for(2s), std::future_status::ready);
    ASSERT_TRUE(fut.get().is_good());
  }
};

// Empty registry => FindServers returns exactly the self ApplicationDescription (self-only).
// Covers SVR-DISC-LDS-002 (coverage-audit retag).
TEST_F(FindServersAggregationTest, EmptyRegistryReturnsSelfOnly)
{
  enable_lds();
  stage_one_listener();

  auto response = run_find_servers(ua::FindServersRequest{});
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  EXPECT_EQ(findResponse->servers().payload().size(), 1u)
    << "empty registry must be identical to the self-only response";
}

// Part 4 sections 5.4 and 5.5.2.2 apply locale negotiation to the self entry too.
// @relation(AC-SVR-DISC-FS-024-FIRST-MATCHING-LOCALE, scope=function)
TEST_F(FindServersAggregationTest, SelfNameUsesRequestedLocalePriorityWithoutChangingIdentity)
{
  stage_one_listener();
  auto identity = ua::ApplicationIdentity::load_default();
  identity.applicationName = ua::LocalizedText{"en", "Self server"}
                               .with_translation("de", "Eigener Server")
                               .with_translation("fr", "Serveur local");
  const auto configuredName = identity.applicationName;
  mDeps->set_identity(std::move(identity));

  const std::vector<std::pair<std::vector<ua::LocaleId>, ua::LocalizedText>> cases{
    {{"fr", "de"}, {"fr", "Serveur local"}},
    {{"de", "fr"}, {"de", "Eigener Server"}},
    {{"es", "fr", "de"}, {"fr", "Serveur local"}},
    {{"es", "de", "fr"}, {"de", "Eigener Server"}},
    {{"es"}, {"en", "Self server"}},
    {{}, {"en", "Self server"}},
    {{"en", "fr"}, {"en", "Self server"}}};
  for (const auto& [requestedLocales, expectedName] : cases)
  {
    SCOPED_TRACE(std::string{expectedName.locale()});
    ua::FindServersRequest request;
    request.locale_ids().payload() = requestedLocales;
    auto response = run_find_servers(std::move(request));
    const auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
    ASSERT_NE(findResponse, nullptr);
    EXPECT_EQ(findResponse->response_header().service_result(), ua::Status::Good);
    ASSERT_EQ(findResponse->servers().size(), 1u);
    const auto& applicationName = findResponse->servers()[0].application_name();
    EXPECT_EQ(applicationName.locale(), expectedName.locale());
    EXPECT_EQ(applicationName.text(), expectedName.text());
    EXPECT_EQ(applicationName.translation_count(), 1u);
    EXPECT_EQ(mDeps->identity().applicationName, configuredName);
  }
}

// One online registration appears alongside self.
TEST_F(FindServersAggregationTest, OnlineRegistrationAppears)
{
  enable_lds();
  stage_one_listener();
  store_registration(make_registered_server("urn:server:registered"));

  auto response = run_find_servers(ua::FindServersRequest{});
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  const auto& servers = findResponse->servers().payload();
  ASSERT_EQ(servers.size(), 2u) << "self + one registered server";

  bool found = false;
  for (const auto& app : servers)
  {
    if (std::string{app.application_uri()} == "urn:server:registered")
      found = true;
  }
  EXPECT_TRUE(found) << "the registered server must surface in FindServers";
}

// @relation(AC-SVR-DISC-FS-024-FIRST-MATCHING-LOCALE, scope=function)
TEST_F(FindServersAggregationTest, RegisteredServerNameUsesFirstSupportedRequestedLocale)
{
  enable_lds();
  stage_one_listener();

  auto registered = make_registered_server("urn:server:localized");
  registered.server_names().payload().clear();
  registered.server_names().payload().push_back(ua::LocalizedText{"de", "Deutscher Name"});
  registered.server_names().payload().push_back(ua::LocalizedText{"fr", "Nom francais"});
  store_registration(registered);

  const auto findRegistered = [](const ua::FindServersResponse& response) -> const ua::ApplicationDescription*
  {
    for (const auto& server : response.servers())
    {
      if (server.application_uri() == "urn:server:localized")
        return &server;
    }
    return nullptr;
  };

  ua::FindServersRequest frenchFirst;
  frenchFirst.locale_ids().push_back("es");
  frenchFirst.locale_ids().push_back("fr");
  frenchFirst.locale_ids().push_back("de");
  auto frenchResponse = run_find_servers(std::move(frenchFirst));
  auto* frenchFindResponse = dynamic_cast<ua::FindServersResponse*>(frenchResponse.second.get());
  ASSERT_NE(frenchFindResponse, nullptr);
  const auto* frenchServer = findRegistered(*frenchFindResponse);
  ASSERT_NE(frenchServer, nullptr);
  EXPECT_EQ(frenchServer->application_name(), ua::LocalizedText("fr", "Nom francais"));

  ua::FindServersRequest germanFirst;
  germanFirst.locale_ids().push_back("es");
  germanFirst.locale_ids().push_back("de");
  germanFirst.locale_ids().push_back("fr");
  auto germanResponse = run_find_servers(std::move(germanFirst));
  auto* germanFindResponse = dynamic_cast<ua::FindServersResponse*>(germanResponse.second.get());
  ASSERT_NE(germanFindResponse, nullptr);
  const auto* germanServer = findRegistered(*germanFindResponse);
  ASSERT_NE(germanServer, nullptr);
  EXPECT_EQ(germanServer->application_name(), ua::LocalizedText("de", "Deutscher Name"));
}

// serverUris filter honoured: a non-matching filter excludes the registration (self still returned).
TEST_F(FindServersAggregationTest, ServerUrisFilterHonoured)
{
  enable_lds();
  stage_one_listener();
  store_registration(make_registered_server("urn:server:registered"));

  ua::FindServersRequest req;
  req.server_uris().payload().push_back(ua::String{"urn:server:some-other"});  // does not match

  auto response = run_find_servers(std::move(req));
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);

  for (const auto& app : findResponse->servers().payload())
  {
    EXPECT_NE(std::string{app.application_uri()}, "urn:server:registered")
      << "a filtered-out registration must not appear";
  }
}

// An offline (evicted) registration is absent from FindServers.
TEST_F(FindServersAggregationTest, OfflineRegistrationAbsent)
{
  enable_lds();
  stage_one_listener();
  store_registration(make_registered_server("urn:server:registered"));
  // Deregister it (isOnline=false) - evicts immediately.
  store_registration(make_registered_server("urn:server:registered", /*online=*/false));

  auto response = run_find_servers(ua::FindServersRequest{});
  auto* findResponse = dynamic_cast<ua::FindServersResponse*>(response.second.get());
  ASSERT_NE(findResponse, nullptr);
  EXPECT_EQ(findResponse->servers().payload().size(), 1u) << "evicted registration must be absent";
}

}  // namespace
}  // namespace ua::test::server::discovery::lds
