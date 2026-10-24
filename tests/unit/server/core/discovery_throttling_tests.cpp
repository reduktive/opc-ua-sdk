// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file Tests for discovery service throttling (S12).
///
/// Verifies that ServerImpl exposes a shared in-flight discovery counter that starts at zero.
/// Config default tests live in server_configuration_defaults_tests.cpp.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_server_configuration.h"
#include "ua_server_impl.h"
#include <boost/asio/thread_pool.hpp>

#include "ua_connection_protocol.h"
#include "ua_find_servers_request.h"
#include "ua_find_servers_response.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_message_security_mode.h"
#include "ua_server_secure_channel.h"
#include "ua_server_secure_channel_test_access.h"
#include "ua_user_token_type.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::server;

using TestAccess = ua::test_helpers::ServerImplTestAccess;

namespace
{

shared_ptr<ServerImpl> create_server(boost::asio::any_io_executor ex, ServerConfig serverConfig = {})
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;

  ::ua::server::CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));

  // Add a minimal listener so validate() passes.
  {
    ServerConfig::ListenerConfig listener;
    listener.name = "TestListener";
    listener.bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
    listener.bind.address = "127.0.0.1:4840";
    listener.externalUrl = ua::transport::EndpointUrl{"opc.tcp://127.0.0.1:4840"};

    ua::server::ServerEndpointConfig ep;
    ep.name = "None";
    ep.messageSecurityMode = ua::MessageSecurityMode::None;
    ep.securityPolicyId = ua::SecurityPolicyId::None;
    ep.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
    listener.endpoints.push_back(std::move(ep));

    serverConfig.listeners().push_back(std::move(listener));
  }

  serverConfig.validate();
  frozen.server = std::move(serverConfig);

  return ua::server::ServerImpl::create(
    ex, std::move(frozen), ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
}

}  // namespace

// ---------------------------------------------------------------------------
// Counter exposed by ServerImpl
// ---------------------------------------------------------------------------

class DiscoveryThrottlingServerTests : public ::testing::Test
{
protected:
  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  boost::asio::thread_pool mPool{1};
  boost::asio::any_io_executor mExecutor{mPool.get_executor()};
};

// @relation(SVR-DISC-FS-019, scope=function)
TEST_F(DiscoveryThrottlingServerTests, CounterIsNonNull)
{
  auto server = create_server(mExecutor);
  auto counter = TestAccess{*server}.in_flight_discovery_requests();
  ASSERT_NE(counter, nullptr);
}

TEST_F(DiscoveryThrottlingServerTests, CounterStartsAtZero)
{
  auto server = create_server(mExecutor);
  auto counter = TestAccess{*server}.in_flight_discovery_requests();
  EXPECT_EQ(counter->load(std::memory_order_relaxed), 0u);
}

TEST_F(DiscoveryThrottlingServerTests, CounterIsSharedAcrossCalls)
{
  auto server = create_server(mExecutor);
  auto counter1 = TestAccess{*server}.in_flight_discovery_requests();
  auto counter2 = TestAccess{*server}.in_flight_discovery_requests();
  EXPECT_EQ(counter1.get(), counter2.get());
}

// ---------------------------------------------------------------------------
// The discovery services themselves, driven over a real SecureChannel
// ---------------------------------------------------------------------------

namespace
{

using SCTA = ua::server::SecureChannelTestAccess;

/// The single listener `create_server` above configures, as both bind address and external URL.
constexpr const char* listenerUrl = "opc.tcp://127.0.0.1:4840";

ServerConfig throttling_config(uint32_t concurrencyThreshold, std::chrono::milliseconds delay)
{
  ServerConfig config;
  config.discoveryThrottling.concurrencyThreshold = concurrencyThreshold;
  config.discoveryThrottling.delayPerRequest = delay;
  return config;
}

/// A real `ServerImpl` plus a real `SecureChannel` built on **that server's own**
/// `SecureChannelDependencies`.
///
/// Nothing here supplies the behaviour under test: the in-flight counter the throttle compares
/// against is the server's, it is incremented by the production dispatch (not by the test), the
/// threshold comes from the server's frozen `ServerConfig`, and the answer is produced by
/// the production `DiscoveryServiceSet` over the server's real listener/endpoint configuration.
/// The test contributes only the injected request and the clock.
class DiscoveryChannel
{
public:
  DiscoveryChannel(boost::asio::any_io_executor executor, ServerConfig serverConfig)
    : mServer(create_server(executor, std::move(serverConfig)))
  {
    TestAccess{*mServer}.initialise_listeners_from_config();

    mChannel = SecureChannel::create(TestAccess{*mServer}.secure_channel_dependencies(),
      nullptr,
      ua::connection_protocol::NegotiatedLimits{},
      ListenerHandle{1},
      "TestListener");

    SCTA::on_strand(*mChannel, [&](auto& g) { g.set_minimal_context_none(executor, "TestListener/None"); });
    SCTA::on_strand(*mChannel, [](auto& g) { g.channel_state() = SCTA::ChannelState::Open; });
    SCTA::on_strand(*mChannel,
      [this](auto& g)
      {
        g.set_response_sink(
          [this](const ua::Response& response)
          {
            {
              const std::lock_guard<std::mutex> lock{mMutex};
              mResponses.push_back(response);
            }
            mResponseArrived.notify_all();
          });
      });
    SCTA::strand_barrier(*mChannel);
  }

  DiscoveryChannel(const DiscoveryChannel&) = delete;
  DiscoveryChannel(DiscoveryChannel&&) = delete;
  DiscoveryChannel& operator=(const DiscoveryChannel&) = delete;
  DiscoveryChannel& operator=(DiscoveryChannel&&) = delete;

  ~DiscoveryChannel()
  {
    if (mChannel)
    {
      // Drop the sink on-strand before this object dies: a response still in flight would otherwise
      // reach a dangling `this`.
      SCTA::on_strand(
        *mChannel, [](auto& g) { g.set_response_sink(std::function<void(const ua::Response&)>{}); });
      mChannel.reset();
    }
    mServer.reset();
  }

  ServerImpl& server()
  {
    return *mServer;
  }

  /// Injects @p request on the open channel and returns how long the server took to answer it.
  std::chrono::milliseconds inject_and_time(uint32_t requestId, shared_ptr<Structure> request)
  {
    ++mInjected;
    const auto expected = mInjected;
    const auto start = std::chrono::steady_clock::now();
    SCTA::on_strand(*mChannel, [&](auto& g) { g.inject_decoded_request(requestId, request, ua::NodeId{}); });

    std::unique_lock<std::mutex> lock{mMutex};
    const bool answered = mResponseArrived.wait_for(
      lock, std::chrono::seconds{10}, [&] { return mResponses.size() >= expected; });
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(answered) << "the discovery request was never answered";
    return std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
  }

  std::vector<ua::Response> responses()
  {
    const std::lock_guard<std::mutex> lock{mMutex};
    return mResponses;
  }

private:
  shared_ptr<ServerImpl> mServer;
  shared_ptr<SecureChannel> mChannel;

  std::mutex mMutex;
  std::condition_variable mResponseArrived;
  std::vector<ua::Response> mResponses;
  std::size_t mInjected{0};
};

std::string response_type_name(const ua::Response& response)
{
  return response.second ? std::string{response.second->type_name()} : std::string{"<null response>"};
}

}  // namespace

class DiscoveryThrottlingChannelTests : public ::testing::Test
{
protected:
  void TearDown() override
  {
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  boost::asio::thread_pool mPool{2};
  boost::asio::any_io_executor mExecutor{mPool.get_executor()};
};

// Part 4 section 5.4.4.1: "The Server should also add a short delay before starting processing of a
// request during high traffic conditions." The clause is conditional, and a plausible
// implementation gets exactly one half of it: it either sleeps on every discovery request (which
// penalises the legitimate, low-rate caller the delay is not aimed at) or it wires the counter up
// and never consults it (which is the whole mitigation missing). Both arms are driven with the
// SAME configured delay, so only the server's own high-traffic classification separates them.
// @verifies AC-SVR-DISC-GE-012-THROTTLE-UNDER-LOAD
TEST_F(DiscoveryThrottlingChannelTests, GetEndpointsIsDelayedOnlyWhileTrafficIsAboveTheThreshold)
{
  constexpr auto delay = std::chrono::milliseconds{600};

  std::chrono::milliseconds underLoad{0};
  {
    // Threshold 0: the in-flight count the server maintains for itself (1, once the production
    // dispatch has counted this request) is above it, so the server classes this as high traffic.
    DiscoveryChannel loaded{mExecutor, throttling_config(0, delay)};

    auto request = std::make_shared<GetEndpointsRequest>();
    request->endpoint_url() = listenerUrl;
    underLoad = loaded.inject_and_time(1, request);

    auto responses = loaded.responses();
    ASSERT_EQ(responses.size(), 1u);
    ASSERT_NE(dynamic_cast<GetEndpointsResponse*>(responses[0].second.get()), nullptr)
      << "a throttled request must be delayed and then answered, never refused; got "
      << response_type_name(responses[0]);
  }

  std::chrono::milliseconds ordinary{0};
  {
    // Same delay, but a threshold a single request cannot exceed - so no delay may apply.
    DiscoveryChannel quiet{mExecutor, throttling_config(1000, delay)};

    auto request = std::make_shared<GetEndpointsRequest>();
    request->endpoint_url() = listenerUrl;
    ordinary = quiet.inject_and_time(1, request);

    auto responses = quiet.responses();
    ASSERT_EQ(responses.size(), 1u);
    ASSERT_NE(dynamic_cast<GetEndpointsResponse*>(responses[0].second.get()), nullptr)
      << "got " << response_type_name(responses[0]);
  }

  EXPECT_GE(underLoad.count(), 400) << "above the high-traffic threshold the configured " << delay.count()
                                    << " ms delay must precede processing; the answer came back in "
                                    << underLoad.count() << " ms";
  EXPECT_LT(ordinary.count(), 300) << "at an ordinary rate the same " << delay.count()
                                   << " ms delay must NOT apply; the answer took " << ordinary.count()
                                   << " ms";
}

// Part 4 section 5.4.2.1: "The Server should also add a short delay before starting processing of a
// request during high traffic conditions." FindServers reaches the throttle through its own
// dispatch arm, so an implementation can easily throttle GetEndpoints and leave the cheaper-looking
// FindServers - the service an attacker reaches first - unthrottled, or throttle it
// unconditionally and penalise the legitimate caller. Both arms are asserted here.
// @verifies AC-SVR-DISC-FS-020-THROTTLE-UNDER-LOAD
TEST_F(DiscoveryThrottlingChannelTests, FindServersIsDelayedOnlyWhileTrafficIsAboveTheThreshold)
{
  constexpr auto delay = std::chrono::milliseconds{600};

  std::chrono::milliseconds underLoad{0};
  {
    DiscoveryChannel loaded{mExecutor, throttling_config(0, delay)};

    auto request = std::make_shared<FindServersRequest>();
    request->endpoint_url() = listenerUrl;
    underLoad = loaded.inject_and_time(1, request);

    auto responses = loaded.responses();
    ASSERT_EQ(responses.size(), 1u);
    ASSERT_NE(dynamic_cast<FindServersResponse*>(responses[0].second.get()), nullptr)
      << "a throttled request must be delayed and then answered, never refused; got "
      << response_type_name(responses[0]);
  }

  std::chrono::milliseconds ordinary{0};
  {
    DiscoveryChannel quiet{mExecutor, throttling_config(1000, delay)};

    auto request = std::make_shared<FindServersRequest>();
    request->endpoint_url() = listenerUrl;
    ordinary = quiet.inject_and_time(1, request);

    auto responses = quiet.responses();
    ASSERT_EQ(responses.size(), 1u);
    ASSERT_NE(dynamic_cast<FindServersResponse*>(responses[0].second.get()), nullptr)
      << "got " << response_type_name(responses[0]);
  }

  EXPECT_GE(underLoad.count(), 400) << "above the high-traffic threshold the configured " << delay.count()
                                    << " ms delay must precede processing; the answer came back in "
                                    << underLoad.count() << " ms";
  EXPECT_LT(ordinary.count(), 300) << "at an ordinary rate the same " << delay.count()
                                   << " ms delay must NOT apply; the answer took " << ordinary.count()
                                   << " ms";
}

// Part 4 section 5.4.4.1: "A Server should minimize the amount of processing required to send the response
// for this Service." GetEndpoints is answered out of the configured listener/endpoint set and
// nothing else. A plausible implementation reaches for the machinery it already has - opening a
// session-like context to carry the call, or caching per-request state keyed by the caller - and
// that shows up as residue the second identical call can see: a session on the server, or an
// in-flight reservation that is never released. Both the content (it mirrors configuration) and
// the absence of residue are asserted.
// @verifies AC-SVR-DISC-GE-011-MINIMAL-PROCESSING
TEST_F(DiscoveryThrottlingChannelTests, GetEndpointsIsServedFromConfigurationWithoutPerRequestState)
{
  DiscoveryChannel channel{mExecutor, ServerConfig{}};

  auto first = std::make_shared<GetEndpointsRequest>();
  first->endpoint_url() = listenerUrl;
  channel.inject_and_time(1, first);

  auto second = std::make_shared<GetEndpointsRequest>();
  second->endpoint_url() = listenerUrl;
  channel.inject_and_time(2, second);

  auto responses = channel.responses();
  ASSERT_EQ(responses.size(), 2u) << "both GetEndpoints calls must be answered";

  std::vector<std::size_t> endpointCounts;
  for (const auto& response : responses)
  {
    auto* typed = dynamic_cast<GetEndpointsResponse*>(response.second.get());
    ASSERT_NE(typed, nullptr) << "GetEndpoints must be answered, not faulted; got "
                              << response_type_name(response);
    EXPECT_TRUE(typed->response_header().service_result().is_good());

    const auto& endpoints = typed->endpoints().payload();
    ASSERT_FALSE(endpoints.empty()) << "the configured listener endpoint must be reported";

    // Every field below is the configured endpoint read back: one listener, one advertised URL,
    // one endpoint, one user token policy - nothing constructed for this request.
    EXPECT_EQ(endpoints.size(), 1u) << "exactly the one configured endpoint, no more";
    EXPECT_NE(std::string{endpoints[0].endpoint_url()}.find("127.0.0.1:4840"), std::string::npos)
      << "the reported URL must be the configured listener's, not a per-request invention: "
      << std::string{endpoints[0].endpoint_url()};
    EXPECT_EQ(endpoints[0].security_mode(), ua::MessageSecurityMode::None);
    EXPECT_FALSE(std::string{endpoints[0].transport_profile_uri()}.empty());

    const auto& tokens = endpoints[0].user_identity_tokens().payload();
    ASSERT_FALSE(tokens.empty()) << "the configured Anonymous user token policy must be reported";
    EXPECT_EQ(tokens[0].token_type(), ua::UserTokenType::Anonymous);

    endpointCounts.push_back(endpoints.size());
  }

  ASSERT_EQ(endpointCounts.size(), 2u);
  EXPECT_EQ(endpointCounts[0], endpointCounts[1])
    << "two identical calls must yield the same configuration-derived answer";

  // No per-request state survives the call.
  EXPECT_TRUE(TestAccess{channel.server()}.sessions().empty())
    << "GetEndpoints is session-less; it must not create session state";

  auto counter = TestAccess{channel.server()}.in_flight_discovery_requests();
  ASSERT_NE(counter, nullptr);
  EXPECT_EQ(counter->load(std::memory_order_relaxed), 0u)
    << "each request's in-flight reservation must be released once its response is produced";
}

// Part 4 section 5.4.2.1: "A Server should minimize the amount of processing required to send the response
// for this Service." FindServers is answered from the frozen application identity plus the
// configured listener set, and from nothing else. A plausible implementation reaches instead for
// the machinery it already owns - a session-like context to carry the session-less call, or the
// address space, reading the description back out of the Server object's ServerArray/namespace
// nodes. Both are far more expensive than the obligation allows, and the second is also wrong here:
// this server is never started, so those node values were never populated. Every field asserted
// below is a configured value read back, and the residue conjuncts - no session state, no retained
// in-flight reservation - are asserted with it.
// @verifies AC-SVR-DISC-FS-019-MINIMAL-PROCESSING
TEST_F(DiscoveryThrottlingChannelTests, FindServersIsServedFromConfigurationWithoutPerRequestState)
{
  DiscoveryChannel channel{mExecutor, ServerConfig{}};

  auto first = std::make_shared<FindServersRequest>();
  first->endpoint_url() = listenerUrl;
  channel.inject_and_time(1, first);

  auto second = std::make_shared<FindServersRequest>();
  second->endpoint_url() = listenerUrl;
  channel.inject_and_time(2, second);

  auto responses = channel.responses();
  ASSERT_EQ(responses.size(), 2u) << "both FindServers calls must be answered";

  std::vector<std::string> applicationUris;
  for (const auto& response : responses)
  {
    auto* typed = dynamic_cast<FindServersResponse*>(response.second.get());
    ASSERT_NE(typed, nullptr) << "FindServers must be answered, not faulted; got "
                              << response_type_name(response);
    EXPECT_TRUE(typed->response_header().service_result().is_good());

    const auto& servers = typed->servers().payload();
    ASSERT_FALSE(servers.empty()) << "the server's own ApplicationDescription must be reported";
    EXPECT_EQ(servers.size(), 1u) << "no registration store is configured, so exactly the self entry";

    const auto& self = servers[0];

    // Identity fields, straight out of the frozen configuration this server was built with:
    // `create_test_config()` allocates the applicationUri and `ApplicationIdentity::load_default()`
    // supplies the productUri and type. Nothing here is derived per request.
    EXPECT_EQ(std::string{self.application_uri()}.rfind("uri://reduktive.com/TestServer/", 0), 0u)
      << "the applicationUri must be the configured one, not a per-request invention: "
      << std::string{self.application_uri()};
    EXPECT_EQ(std::string{self.product_uri()}, std::string{"http://reduktive.com/OPCUA/SDK/Server"});
    EXPECT_EQ(self.application_type(), ua::ApplicationType::Server);
    EXPECT_FALSE(std::string{self.application_name().text()}.empty())
      << "the configured application name must be reported";

    const auto& urls = self.discovery_urls().payload();
    ASSERT_FALSE(urls.empty()) << "the configured listener must be advertised as a discovery URL";
    bool advertisesConfiguredListener = false;
    for (const auto& url : urls)
    {
      if (std::string{url}.find("127.0.0.1:4840") != std::string::npos)
      {
        advertisesConfiguredListener = true;
      }
    }
    EXPECT_TRUE(advertisesConfiguredListener)
      << "the advertised discovery URL must be the configured listener's";

    applicationUris.push_back(std::string{self.application_uri()});
  }

  ASSERT_EQ(applicationUris.size(), 2u);
  EXPECT_EQ(applicationUris[0], applicationUris[1])
    << "two identical calls must yield the same configuration-derived answer";

  // No per-request state survives the call.
  EXPECT_TRUE(TestAccess{channel.server()}.sessions().empty())
    << "FindServers is session-less; it must not create session state";

  auto counter = TestAccess{channel.server()}.in_flight_discovery_requests();
  ASSERT_NE(counter, nullptr);
  EXPECT_EQ(counter->load(std::memory_order_relaxed), 0u)
    << "each request's in-flight reservation must be released once its response is produced";
}

// Part 4 section 5.4.4.1: the delay is owed "during high traffic conditions" only, so the server must both
// apply it above its own in-flight threshold and stop applying it once traffic subsides. The second
// half is what a plausible implementation loses: it reserves the in-flight slot on the way in but
// releases it only on the immediate-dispatch path, so the first throttled request leaves the count
// permanently raised and every later caller - including the legitimate low-rate one this delay is
// not aimed at - is delayed for the life of the server. That is invisible to a single-request test,
// so the ordinary-rate arm here issues a second request whose promptness is the evidence that the
// first request's reservation was released.
// @verifies AC-SVR-DISC-GE-012-THROTTLE-UNDER-LOAD
TEST_F(DiscoveryThrottlingChannelTests, GetEndpointsDelayAppliesUnderLoadAndIsNotLeftLatchedOn)
{
  constexpr auto delay = std::chrono::milliseconds{600};

  {
    // Threshold 0: one in-flight request is already above it, so the server classes this as high
    // traffic and must delay before processing.
    DiscoveryChannel loaded{mExecutor, throttling_config(0, delay)};

    auto request = std::make_shared<GetEndpointsRequest>();
    request->endpoint_url() = listenerUrl;
    const auto underLoad = loaded.inject_and_time(1, request);

    auto responses = loaded.responses();
    ASSERT_EQ(responses.size(), 1u);
    ASSERT_NE(dynamic_cast<GetEndpointsResponse*>(responses[0].second.get()), nullptr)
      << "a throttled request must be delayed and then answered, never refused; got "
      << response_type_name(responses[0]);

    EXPECT_GE(underLoad.count(), 400)
      << "above the high-traffic threshold the configured " << delay.count()
      << " ms delay must precede processing; the answer came back in " << underLoad.count() << " ms";

    auto counter = TestAccess{loaded.server()}.in_flight_discovery_requests();
    ASSERT_NE(counter, nullptr);
    EXPECT_EQ(counter->load(std::memory_order_relaxed), 0u)
      << "the delayed path must release its in-flight reservation too, or the server stays latched "
         "in the high-traffic state for good";
  }

  {
    // Threshold 1: a single request at a time never exceeds it, so the same configured delay must
    // not apply - to the first call, nor to the second, which is only prompt if the first call's
    // reservation was given back.
    DiscoveryChannel quiet{mExecutor, throttling_config(1, delay)};

    auto first = std::make_shared<GetEndpointsRequest>();
    first->endpoint_url() = listenerUrl;
    const auto firstElapsed = quiet.inject_and_time(1, first);

    auto second = std::make_shared<GetEndpointsRequest>();
    second->endpoint_url() = listenerUrl;
    const auto secondElapsed = quiet.inject_and_time(2, second);

    auto responses = quiet.responses();
    ASSERT_EQ(responses.size(), 2u);
    for (const auto& response : responses)
    {
      ASSERT_NE(dynamic_cast<GetEndpointsResponse*>(response.second.get()), nullptr)
        << "got " << response_type_name(response);
    }

    EXPECT_LT(firstElapsed.count(), 300)
      << "at an ordinary rate the configured " << delay.count()
      << " ms delay must NOT apply; the answer took " << firstElapsed.count() << " ms";
    EXPECT_LT(secondElapsed.count(), 300)
      << "the second ordinary-rate call must be just as prompt; it took " << secondElapsed.count()
      << " ms, which is the signature of an in-flight count that was never given back";

    auto counter = TestAccess{quiet.server()}.in_flight_discovery_requests();
    ASSERT_NE(counter, nullptr);
    EXPECT_EQ(counter->load(std::memory_order_relaxed), 0u);
  }
}

// Part 4 section 5.4.2.1, the FindServers twin: the delay is owed only "during high traffic conditions".
// FindServers reaches the throttle through its own dispatch arm, so an implementation can throttle
// GetEndpoints correctly and still get this one wrong - and the failure that survives a
// single-request test is the reservation that is released only on the immediate-dispatch path,
// which latches the server into the delayed state and penalises exactly the legitimate caller the
// clause exempts. Both conjuncts are asserted, and the ordinary-rate arm issues a second request so
// the latch is observable.
// @verifies AC-SVR-DISC-FS-020-THROTTLE-UNDER-LOAD
TEST_F(DiscoveryThrottlingChannelTests, FindServersDelayAppliesUnderLoadAndIsNotLeftLatchedOn)
{
  constexpr auto delay = std::chrono::milliseconds{600};

  {
    DiscoveryChannel loaded{mExecutor, throttling_config(0, delay)};

    auto request = std::make_shared<FindServersRequest>();
    request->endpoint_url() = listenerUrl;
    const auto underLoad = loaded.inject_and_time(1, request);

    auto responses = loaded.responses();
    ASSERT_EQ(responses.size(), 1u);
    ASSERT_NE(dynamic_cast<FindServersResponse*>(responses[0].second.get()), nullptr)
      << "a throttled request must be delayed and then answered, never refused; got "
      << response_type_name(responses[0]);

    EXPECT_GE(underLoad.count(), 400)
      << "above the high-traffic threshold the configured " << delay.count()
      << " ms delay must precede processing; the answer came back in " << underLoad.count() << " ms";

    auto counter = TestAccess{loaded.server()}.in_flight_discovery_requests();
    ASSERT_NE(counter, nullptr);
    EXPECT_EQ(counter->load(std::memory_order_relaxed), 0u)
      << "the delayed path must release its in-flight reservation too, or the server stays latched "
         "in the high-traffic state for good";
  }

  {
    DiscoveryChannel quiet{mExecutor, throttling_config(1, delay)};

    auto first = std::make_shared<FindServersRequest>();
    first->endpoint_url() = listenerUrl;
    const auto firstElapsed = quiet.inject_and_time(1, first);

    auto second = std::make_shared<FindServersRequest>();
    second->endpoint_url() = listenerUrl;
    const auto secondElapsed = quiet.inject_and_time(2, second);

    auto responses = quiet.responses();
    ASSERT_EQ(responses.size(), 2u);
    for (const auto& response : responses)
    {
      ASSERT_NE(dynamic_cast<FindServersResponse*>(response.second.get()), nullptr)
        << "got " << response_type_name(response);
    }

    EXPECT_LT(firstElapsed.count(), 300)
      << "at an ordinary rate the configured " << delay.count()
      << " ms delay must NOT apply; the answer took " << firstElapsed.count() << " ms";
    EXPECT_LT(secondElapsed.count(), 300)
      << "the second ordinary-rate call must be just as prompt; it took " << secondElapsed.count()
      << " ms, which is the signature of an in-flight count that was never given back";

    auto counter = TestAccess{quiet.server()}.in_flight_discovery_requests();
    ASSERT_NE(counter, nullptr);
    EXPECT_EQ(counter->load(std::memory_order_relaxed), 0u);
  }
}

// Part 4 section 5.4.4.1: "A Server should minimize the amount of processing required to send the response
// for this Service." The answer is a projection of the configured endpoint set, so it must be the
// same on every call and it must carry the configured application identity - an implementation that
// assembles per-request state, or that resolves the ApplicationDescription out of the address space
// rather than out of configuration, drifts between calls or leaves the embedded description blank
// (this server is never started, so the node values such an implementation would read were never
// populated). Comparing endpoint counts alone would not see either failure, so the whole projected
// tuple is compared across two calls, and the residue conjuncts are asserted with it.
// @verifies AC-SVR-DISC-GE-011-MINIMAL-PROCESSING
TEST_F(DiscoveryThrottlingChannelTests, GetEndpointsProjectsTheConfiguredIdentityIdenticallyOnEveryCall)
{
  DiscoveryChannel channel{mExecutor, ServerConfig{}};

  auto first = std::make_shared<GetEndpointsRequest>();
  first->endpoint_url() = listenerUrl;
  channel.inject_and_time(1, first);

  auto second = std::make_shared<GetEndpointsRequest>();
  second->endpoint_url() = listenerUrl;
  channel.inject_and_time(2, second);

  auto responses = channel.responses();
  ASSERT_EQ(responses.size(), 2u) << "both GetEndpoints calls must be answered";

  // One entry per call: the whole projected description, flattened so the two are comparable.
  std::vector<std::string> projections;
  for (const auto& response : responses)
  {
    auto* typed = dynamic_cast<GetEndpointsResponse*>(response.second.get());
    ASSERT_NE(typed, nullptr) << "GetEndpoints must be answered, not faulted; got "
                              << response_type_name(response);
    EXPECT_TRUE(typed->response_header().service_result().is_good());

    const auto& endpoints = typed->endpoints().payload();
    ASSERT_FALSE(endpoints.empty()) << "the configured listener endpoint must be reported";

    std::string projection;
    for (const auto& endpoint : endpoints)
    {
      // The ApplicationDescription embedded in every EndpointDescription is the configured
      // identity, not something built for this request.
      const auto& self = endpoint.server();
      EXPECT_EQ(std::string{self.application_uri()}.rfind("uri://reduktive.com/TestServer/", 0), 0u)
        << "the embedded applicationUri must be the configured one: " << std::string{self.application_uri()};
      EXPECT_EQ(std::string{self.product_uri()}, std::string{"http://reduktive.com/OPCUA/SDK/Server"});
      EXPECT_EQ(self.application_type(), ua::ApplicationType::Server);
      EXPECT_FALSE(std::string{self.application_name().text()}.empty())
        << "the configured application name must be reported";
      EXPECT_FALSE(std::string{endpoint.security_policy_uri()}.empty());

      projection += std::string{endpoint.endpoint_url()};
      projection += '|';
      projection += std::string{endpoint.security_policy_uri()};
      projection += '|';
      projection += std::to_string(static_cast<int>(endpoint.security_mode()));
      projection += '|';
      projection += std::string{self.application_uri()};
      projection += '|';
      projection += std::to_string(endpoint.user_identity_tokens().payload().size());
      projection += ';';
    }

    ASSERT_FALSE(projection.empty());
    projections.push_back(std::move(projection));
  }

  ASSERT_EQ(projections.size(), 2u);
  EXPECT_EQ(projections[0], projections[1])
    << "two identical calls must project the same configuration; a difference is per-request state";

  // No per-request state survives the calls.
  EXPECT_TRUE(TestAccess{channel.server()}.sessions().empty())
    << "GetEndpoints is session-less; it must not create session state";

  auto counter = TestAccess{channel.server()}.in_flight_discovery_requests();
  ASSERT_NE(counter, nullptr);
  EXPECT_EQ(counter->load(std::memory_order_relaxed), 0u)
    << "each request's in-flight reservation must be released once its response is produced";
}
