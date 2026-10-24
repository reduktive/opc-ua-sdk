// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "channel_layer_harness.h"
#include "fuzz_client.h"

#include "fuzz_security_policy.h"
#include "mutation_engine.h"

#include "ua_application_configuration.h"
#include "ua_log_sink_implementations.h"
#include "ua_logger.h"
#include "ua_client.h"
#include "ua_client_test_hooks.h"
#include "ua_crypto_types.h"
#include "ua_message_security_mode.h"
#include "ua_read_request.h"
#include "ua_security_policy.h"
#include "ua_session_attribute_services.h"
#include "ua_server.h"
#include "ua_server_config_bundle.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_server_authentication.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_transport_address.h"

#include <algorithm>
#include <chrono>
#include <mutex>

namespace fuzz
{

namespace
{

struct ChannelServerFixture
{
  boost::asio::thread_pool serverPool;
  boost::asio::thread_pool clientPool;
  std::optional<ua::server::Server> server;
  std::string endpointUrl;
  ua::server::ListenerHandle listener{0};

  void start()
  {
    auto appCfg = ua::ApplicationConfig::load_default();
    appCfg.allowInsecureEndpoints = true;
    // Required: published as Server.ServerArray[0] and as the URI of the server's own namespace.
    appCfg.application_description_part().applicationUri = "urn:reduktive:opcua-sdk:fuzz:channel-layer";
    // Short timeouts for fuzzing - corrupted messages must not cause long waits.
    appCfg.stack_limits().connectionProtocolMessageReadTimeout = std::chrono::milliseconds{500};

    ua::server::CreateConfig createCfg{.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = ua::server::ServerConfig{}};

    ua::server::ServerComponents components;
    components.crypto = ua::create_default_crypto();
    components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();
    components.logSink = std::make_shared<ua::ConsoleLogSink>();
    components.logLevel = ua::LogLevel::Debug;

    server.emplace(
      ua::server::Server::create(serverPool.get_executor(), std::move(createCfg), std::move(components)));

    ua::server::ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = ua::MessageSecurityMode::None;
    endpoint.securityPolicyId = ua::SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));

    ua::transport::BindAddress bind;
    bind.address = "127.0.0.1:0";

    listener = server->listen_sync(std::move(bind), {});
    server->add_endpoint(listener, endpoint);
    server->start_sync();

    auto urls = server->advertised_urls(listener);
    endpointUrl = urls.front().str();
  }

  void stop()
  {
    server.reset();
    clientPool.join();
    serverPool.join();
  }
};

/// Interceptor state shared with FuzzSecurityPolicy
struct ChannelInterceptorState
{
  std::mutex mutex;
  MutationEngine* engine{nullptr};
  bool mutateEnabled{false};
  MutationStrategy lastStrategy{MutationStrategy::BitFlip};
  std::vector<uint8_t> lastMutatedBytes;
};

ua::client::ClientTestHooks make_channel_fuzz_hooks(std::shared_ptr<ChannelInterceptorState> state)
{
  ua::client::ClientTestHooks hooks;
  hooks.securityPolicyFactory = [state](ua::SecurityPolicyId policyId) -> std::shared_ptr<ua::SecurityPolicy>
  {
    auto inner = ua::SecurityPolicy::create(policyId);
    auto fuzzPolicy = std::make_shared<opcua_fuzzer::FuzzSecurityPolicy>(std::move(inner));

    fuzzPolicy->set_encode_interceptor(
      [state](ua::ByteString chunk) -> ua::ByteString
      {
        std::lock_guard lock(state->mutex);
        if (!state->mutateEnabled || !state->engine)
        {
          return chunk;
        }

        std::vector<uint8_t> buffer(chunk.begin(), chunk.end());

        state->lastStrategy = state->engine->mutate(buffer);
        state->lastMutatedBytes = buffer;

        return ua::ByteString{std::move(buffer)};
      });

    return fuzzPolicy;
  };

  return hooks;
}

// Channel open lives on the tier-0 CoreClient: this harness fuzzes the raw OPN/session wire
// flow, which is exactly the surface tier-0 exposes and tier-1 deliberately does not.
ua::client::CoreClient::OpenChannelConfig make_channel_fuzz_config(const std::string& endpointUrl)
{
  ua::client::CoreClient::OpenChannelConfig channelConfig;
  channelConfig.endpointUrl = endpointUrl;
  channelConfig.securityMode = ua::MessageSecurityMode::None;
  channelConfig.securityPolicyId = ua::SecurityPolicyId::None;
  return channelConfig;
}

/// Channel-level fuzz scenario types
enum class ChannelScenario
{
  /// Open channel with mutation during OPN handshake
  MutatedHandshake,
  /// Create session with mutated messages
  MutatedCreateSession,
  /// Activate session with mutated messages
  MutatedActivateSession,
  /// Rapid open/close cycling (stress test)
  RapidOpenClose,
  /// Full connect-session-request with mutation throughout
  FullFlowMutated
};

/// Helper to disable mutation under lock.
void disable_mutation(std::shared_ptr<ChannelInterceptorState>& state)
{
  std::lock_guard lock(state->mutex);
  state->mutateEnabled = false;
}

/// Helper to enable mutation under lock.
void enable_mutation(std::shared_ptr<ChannelInterceptorState>& state)
{
  std::lock_guard lock(state->mutex);
  state->mutateEnabled = true;
}

void run_channel_case(ua::client::Client& client, const std::string& endpointUrl,
  std::shared_ptr<ChannelInterceptorState> state, ChannelScenario scenario, Monitor& monitor,
  Reporter& reporter, uint64_t caseNum)
{
  Monitor::CaseOutcome outcome;
  outcome.caseNumber = caseNum;
  outcome.layer = FuzzLayer::SecureChannel;
  outcome.service = FuzzService::GetEndpoints;  // Closest match for channel-level ops

  auto start = std::chrono::steady_clock::now();
  try
  {
    switch (scenario)
    {
    case ChannelScenario::MutatedHandshake:
    {
      // Mutate from the start - OPN messages get mutated
      enable_mutation(state);
      auto channelConfig = make_channel_fuzz_config(endpointUrl);
      auto channelResult = client.core().try_open_channel_sync(channelConfig);
      disable_mutation(state);
      if (!channelResult.is_good())
      {
        outcome.statusCode = channelResult.status_code().as_uint32();
        break;
      }
      std::move(channelResult).value().try_close_sync();
      break;
    }

    case ChannelScenario::MutatedCreateSession:
    {
      // Clean channel open, then mutate during CreateSession
      auto channelConfig = make_channel_fuzz_config(endpointUrl);
      auto channelResult = client.core().try_open_channel_sync(channelConfig);
      if (!channelResult.is_good())
      {
        outcome.statusCode = channelResult.status_code().as_uint32();
        break;
      }
      auto channel = std::move(channelResult).value();
      enable_mutation(state);
      auto sessionResult = channel.try_create_session_sync({});
      disable_mutation(state);
      if (!sessionResult.is_good())
      {
        outcome.statusCode = sessionResult.status_code().as_uint32();
        channel.try_close_sync();
        break;
      }
      std::move(sessionResult).value().try_close_sync();
      channel.try_close_sync();
      break;
    }

    case ChannelScenario::MutatedActivateSession:
    {
      // Clean channel + create, mutate during activate
      auto channelConfig = make_channel_fuzz_config(endpointUrl);
      auto channelResult = client.core().try_open_channel_sync(channelConfig);
      if (!channelResult.is_good())
      {
        outcome.statusCode = channelResult.status_code().as_uint32();
        break;
      }
      auto channel = std::move(channelResult).value();
      auto sessionResult = channel.try_create_session_sync({});
      if (!sessionResult.is_good())
      {
        outcome.statusCode = sessionResult.status_code().as_uint32();
        channel.try_close_sync();
        break;
      }
      auto session = std::move(sessionResult).value();
      enable_mutation(state);
      auto activateResult = session.try_activate_sync();
      disable_mutation(state);
      if (!activateResult.is_good())
      {
        outcome.statusCode = activateResult.status_code().as_uint32();
        session.try_close_sync();
        channel.try_close_sync();
        break;
      }
      session.try_close_sync();
      channel.try_close_sync();
      break;
    }

    case ChannelScenario::RapidOpenClose:
    {
      // Rapid open/close without mutation - stress the channel state machine
      for (int i = 0; i < 5; ++i)
      {
        auto channelConfig = make_channel_fuzz_config(endpointUrl);
        auto channelResult = client.core().try_open_channel_sync(channelConfig);
        if (channelResult.is_good())
        {
          std::move(channelResult).value().try_close_sync();
        }
      }
      break;
    }

    case ChannelScenario::FullFlowMutated:
    {
      // Full flow with mutation throughout
      enable_mutation(state);
      auto channelConfig = make_channel_fuzz_config(endpointUrl);
      auto channelResult = client.core().try_open_channel_sync(channelConfig);
      if (!channelResult.is_good())
      {
        disable_mutation(state);
        outcome.statusCode = channelResult.status_code().as_uint32();
        break;
      }
      auto channel = std::move(channelResult).value();
      auto sessionResult = channel.try_create_session_sync({});
      if (!sessionResult.is_good())
      {
        disable_mutation(state);
        outcome.statusCode = sessionResult.status_code().as_uint32();
        channel.try_close_sync();
        break;
      }
      auto session = std::move(sessionResult).value();
      auto activateResult = session.try_activate_sync();
      if (!activateResult.is_good())
      {
        disable_mutation(state);
        outcome.statusCode = activateResult.status_code().as_uint32();
        session.try_close_sync();
        channel.try_close_sync();
        break;
      }

      // Send a simple Read to exercise the full path
      ua::ReadRequest req;
      ua::ReadValueId rv;
      rv.node_id() = ua::NodeId{0, 2255};  // Server_ServerStatus
      rv.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
      req.nodes_to_read().push_back(std::move(rv));
      session.attributes().try_read_sync(std::move(req));

      disable_mutation(state);
      session.try_close_sync();
      channel.try_close_sync();
      break;
    }
    }
  }
  catch (...)
  {
    disable_mutation(state);

    // A real unhandled exception - genuine finding since we used try_*_sync
    // for all expected failure points.
    outcome.exceptionThrown = true;
    try
    {
      throw;
    }
    catch (const std::exception& e)
    {
      outcome.exceptionMessage = e.what();
    }
    catch (...)
    {
      outcome.exceptionMessage = "unknown exception";
    }
  }
  auto elapsed = std::chrono::steady_clock::now() - start;
  outcome.latency = std::chrono::duration_cast<std::chrono::microseconds>(elapsed);

  if (auto finding = monitor.record(outcome))
  {
    {
      std::lock_guard lock(state->mutex);
      finding->triggerBytes = state->lastMutatedBytes;
      finding->strategy = state->lastStrategy;
    }
    finding->layer = FuzzLayer::SecureChannel;
    reporter.report_finding(*finding);
  }
}

}  // namespace

void run_channel_layer_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger)
{
  auto log = logger.with_category("channel");

  log.info("Starting in-process server");

  ChannelServerFixture fixture;
  fixture.start();

  log.info("Server listening on {}", fixture.endpointUrl);
  log.info("Starting channel fuzz loop");

  auto state = std::make_shared<ChannelInterceptorState>();
  MutationEngine mutationEngine(config.campaign.rngSeed);
  state->engine = &mutationEngine;

  ua::client::CreateConfig clientConfig = fuzz::make_insecure_client_config();
  clientConfig.application.stack_limits().connectionProtocolMessageReadTimeout =
    std::chrono::milliseconds{500};
  clientConfig.client.defaultServiceTimeout = std::chrono::seconds{2};
  std::optional<ua::client::Client> client{ua::client::Client::create(fixture.clientPool.get_executor(),
    std::move(clientConfig),
    {.crypto = ua::create_default_crypto(),
      .logSink = std::make_shared<ua::ConsoleLogSink>(),
      .logLevel = ua::LogLevel::Debug})};
  ua::client::CoreClientTestAccess::set_test_hooks(client->core(), make_channel_fuzz_hooks(state));

  std::mt19937_64 rng(config.campaign.rngSeed != 0 ? config.campaign.rngSeed : std::random_device{}());

  constexpr int numScenarios = 5;
  const ChannelScenario scenarios[] = {
    ChannelScenario::MutatedHandshake,
    ChannelScenario::MutatedCreateSession,
    ChannelScenario::MutatedActivateSession,
    ChannelScenario::RapidOpenClose,
    ChannelScenario::FullFlowMutated,
  };

  auto maxCases = config.campaign.maxCases;
  auto startTime = std::chrono::steady_clock::now();

  for (uint64_t caseNum = 1; maxCases == 0 || caseNum <= maxCases; ++caseNum)
  {
    auto scenarioIdx = std::uniform_int_distribution<int>(0, numScenarios - 1)(rng);
    const char* scenarioNames[] = {"MutatedHandshake",
      "MutatedCreateSession",
      "MutatedActivateSession",
      "RapidOpenClose",
      "FullFlowMutated"};
    log.trace("Case {}: scenario={}", caseNum, scenarioNames[scenarioIdx]);
    run_channel_case(*client, fixture.endpointUrl, state, scenarios[scenarioIdx], monitor, reporter, caseNum);

    auto elapsed = std::chrono::steady_clock::now() - startTime;
    auto elapsedSec = std::chrono::duration<double>(elapsed).count();
    auto rate = elapsedSec > 0 ? static_cast<double>(caseNum) / elapsedSec : 0.0;
    reporter.update_status(caseNum, rate, FuzzLayer::SecureChannel, monitor.server_alive());
  }

  auto totalElapsed = std::chrono::steady_clock::now() - startTime;
  auto totalSec = std::chrono::duration<double>(totalElapsed).count();

  log.info("Fuzz loop complete");

  FuzzResult result;
  result.totalCases = maxCases;
  result.elapsedSeconds = totalSec;
  result.casesPerSecond = maxCases > 0 ? static_cast<double>(maxCases) / totalSec : 0.0;
  result.findingsDir = config.reporting.outputDir;

  auto findings = reporter.findings();
  for (const auto& f : findings)
  {
    switch (f.findingClass)
    {
    case FindingClass::SecurityCrash:
    case FindingClass::SecurityAsanViolation:
      ++result.crashes;
      break;
    case FindingClass::SecurityAuthBypass:
    case FindingClass::SecurityPrivEscalation:
    case FindingClass::SecurityHang:
    case FindingClass::SecurityUnexpectedDisconnect:
    case FindingClass::SecurityDosDegradation:
    case FindingClass::SecurityStateMachineViolation:
    case FindingClass::SecurityReplayAccepted:
      ++result.securityFindings;
      break;
    case FindingClass::MemoryLeak:
    case FindingClass::MemoryLeakSlow:
      ++result.memoryLeaks;
      break;
    case FindingClass::ResourceLeakSession:
    case FindingClass::ResourceLeakChannel:
    case FindingClass::ResourceLeakSubscription:
    case FindingClass::ResourceLeakFd:
      ++result.resourceLeaks;
      break;
    case FindingClass::PerfLatencySpike:
    case FindingClass::PerfLatencyDrift:
    case FindingClass::PerfThroughputDegradation:
    case FindingClass::PerfSlowHandshake:
      ++result.perfFindings;
      break;
    default:
      ++result.criticalBehaviour;
      break;
    }
  }

  reporter.write_summary(result);

  // Destroy the client before stopping the thread pools. The client may hold resources
  // (e.g. CertificateStoreFiles with a periodic refresh timer) that keep the io_context busy.
  client.reset();

  log.debug("Stopping fixture");
  fixture.stop();
  log.debug("Fixture stopped");
}

}  // namespace fuzz
