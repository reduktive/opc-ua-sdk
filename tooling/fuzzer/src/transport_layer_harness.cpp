// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "transport_layer_harness.h"
#include "fuzz_client.h"

#include "fuzz_transport_connection.h"
#include "input_generators.h"
#include "mutation_engine.h"

#include "ua_application_configuration.h"
#include "ua_browse_request.h"
#include "ua_client.h"
#include "ua_client_test_hooks.h"
#include "ua_crypto_types.h"
#include "ua_message_security_mode.h"
#include "ua_read_request.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_server.h"
#include "ua_server_config_bundle.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_server_authentication.h"
#include <boost/asio/thread_pool.hpp>
#include <optional>
#include "ua_transport_address.h"
#include "ua_write_request.h"

#include "ua_logger.h"

#include <algorithm>
#include <chrono>
#include <mutex>

namespace fuzz
{

namespace
{

struct TransportServerFixture
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
    appCfg.application_description_part().applicationUri = "urn:reduktive:opcua-sdk:fuzz:transport-layer";

    ua::server::CreateConfig createCfg{.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = ua::server::ServerConfig{}};

    ua::server::ServerComponents components;
    components.crypto = ua::create_default_crypto();
    components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();

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

/// Shared state for the transport write interceptor.
struct TransportInterceptorState
{
  std::mutex mutex;
  MutationEngine* engine{nullptr};
  bool mutateEnabled{false};
  MutationStrategy lastStrategy{MutationStrategy::BitFlip};
  std::vector<uint8_t> lastOriginalBytes;
  std::vector<uint8_t> lastMutatedBytes;
};

ua::client::ClientTestHooks make_transport_test_hooks(std::shared_ptr<TransportInterceptorState> state)
{
  ua::client::ClientTestHooks hooks;
  hooks.transportDecorator =
    [state](std::shared_ptr<ua::TransportConnection> inner) -> std::shared_ptr<ua::TransportConnection>
  {
    auto fuzzConn = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));

    fuzzConn->set_write_interceptor(
      [state](std::vector<std::byte> buffer) -> std::vector<std::byte>
      {
        std::lock_guard lock(state->mutex);
        if (!state->mutateEnabled || !state->engine)
        {
          return buffer;
        }

        // Convert std::byte -> uint8_t for the mutation engine
        std::vector<uint8_t> u8buf(buffer.size());
        std::transform(
          buffer.begin(), buffer.end(), u8buf.begin(), [](std::byte b) { return static_cast<uint8_t>(b); });

        state->lastOriginalBytes = u8buf;

        // Apply mutation
        state->lastStrategy = state->engine->mutate(u8buf);
        state->lastMutatedBytes = u8buf;

        // Convert back uint8_t -> std::byte
        std::vector<std::byte> result(u8buf.size());
        std::transform(
          u8buf.begin(), u8buf.end(), result.begin(), [](uint8_t b) { return static_cast<std::byte>(b); });
        return result;
      });

    return fuzzConn;
  };

  return hooks;
}

ua::client::CoreClient::OpenChannelConfig make_transport_channel_config(const std::string& endpointUrl)
{
  ua::client::CoreClient::OpenChannelConfig channelConfig;
  channelConfig.endpointUrl = endpointUrl;
  channelConfig.securityMode = ua::MessageSecurityMode::None;
  channelConfig.securityPolicyId = ua::SecurityPolicyId::None;
  return channelConfig;
}

}  // namespace

void run_transport_layer_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger)
{
  auto log = logger.with_category("transport");
  log.info("Starting in-process server");

  TransportServerFixture fixture;
  fixture.start();

  log.info("Server listening on {}", fixture.endpointUrl);
  log.info("Connecting client with FuzzTransportConnection");

  auto state = std::make_shared<TransportInterceptorState>();
  MutationEngine mutationEngine(config.campaign.rngSeed);
  state->engine = &mutationEngine;

  // Optional so it can be destroyed BEFORE fixture.stop() joins the client pool: a live Client
  // holds outstanding work on that pool, and join() would wait on it forever.
  std::optional<ua::client::Client> client{std::in_place,
    ua::client::Client::create(fixture.clientPool.get_executor(),
      fuzz::make_insecure_client_config(),
      {.crypto = ua::create_default_crypto()})};
  ua::client::CoreClientTestAccess::set_test_hooks(client->core(), make_transport_test_hooks(state));

  std::mt19937_64 rng(config.campaign.rngSeed != 0 ? config.campaign.rngSeed : std::random_device{}());

  ReadRequestGenerator readGen(rng, config.limits);
  BrowseRequestGenerator browseGen(rng, config.limits);
  WriteRequestGenerator writeGen(rng, config.limits);

  const FuzzService services[] = {FuzzService::Read, FuzzService::Browse, FuzzService::Write};

  auto maxCases = config.campaign.maxCases;
  auto startTime = std::chrono::steady_clock::now();

  for (uint64_t caseNum = 1; maxCases == 0 || caseNum <= maxCases; ++caseNum)
  {
    // Each case: connect, enable mutation, send a request, observe outcome, disconnect.
    // Reconnecting each time tests the transport handshake (HEL/ACK) path too.
    Monitor::CaseOutcome outcome;
    outcome.caseNumber = caseNum;
    outcome.layer = FuzzLayer::TransportFraming;
    auto serviceChoice = std::uniform_int_distribution<int>(0, 2)(rng);
    outcome.service = services[serviceChoice];

    auto start = std::chrono::steady_clock::now();
    try
    {
      auto channelConfig = make_transport_channel_config(fixture.endpointUrl);

      // Enable mutation - this means the HEL message and all subsequent writes get mutated
      {
        std::lock_guard lock(state->mutex);
        state->mutateEnabled = true;
        state->lastOriginalBytes.clear();
        state->lastMutatedBytes.clear();
      }

      // Use try_*_sync to get Result<T> instead of throwing - transport mutations are
      // expected to cause protocol failures, so exceptions here are not findings.
      auto channelResult = client->core().try_open_channel_sync(channelConfig);
      if (!channelResult.is_good())
      {
        outcome.statusCode = channelResult.status_code().as_uint32();
        std::lock_guard lock(state->mutex);
        state->mutateEnabled = false;
      }
      else
      {
        auto channel = std::move(channelResult).value();

        auto sessionResult = channel.try_create_session_sync({});
        if (!sessionResult.is_good())
        {
          outcome.statusCode = sessionResult.status_code().as_uint32();
          std::lock_guard lock(state->mutex);
          state->mutateEnabled = false;
          channel.try_close_sync();
        }
        else
        {
          auto session = std::move(sessionResult).value();

          auto activateResult = session.try_activate_sync();
          if (!activateResult.is_good())
          {
            outcome.statusCode = activateResult.status_code().as_uint32();
            std::lock_guard lock(state->mutex);
            state->mutateEnabled = false;
            session.try_close_sync();
            channel.try_close_sync();
          }
          else
          {
            // Send one service request
            switch (outcome.service)
            {
            case FuzzService::Read:
            {
              ua::ReadRequest req;
              req.nodes_to_read().push_back(readGen.generate_read_value_id());
              req.timestamps_to_return() = readGen.generate_timestamps_to_return();
              auto resp = session.attributes().try_read_sync(std::move(req));
              if (!resp.is_good())
              {
                outcome.statusCode = resp.status_code().as_uint32();
              }
              break;
            }
            case FuzzService::Browse:
            {
              ua::BrowseRequest req;
              req.nodes_to_browse().push_back(browseGen.generate_browse_description());
              auto resp = session.view().try_browse_sync(std::move(req));
              if (!resp.is_good())
              {
                outcome.statusCode = resp.status_code().as_uint32();
              }
              break;
            }
            case FuzzService::Write:
            {
              ua::WriteRequest req;
              req.nodes_to_write().push_back(writeGen.generate_write_value());
              auto resp = session.attributes().try_write_sync(std::move(req));
              if (!resp.is_good())
              {
                outcome.statusCode = resp.status_code().as_uint32();
              }
              break;
            }
            default:
              break;
            }

            // Disable mutation for clean close
            {
              std::lock_guard lock(state->mutex);
              state->mutateEnabled = false;
            }

            session.try_close_sync();
            channel.try_close_sync();
          }
        }
      }
    }
    catch (...)
    {
      // Disable mutation
      {
        std::lock_guard lock(state->mutex);
        state->mutateEnabled = false;
      }

      // A real unhandled exception - this is a genuine finding since we used try_*_sync
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
      finding->layer = FuzzLayer::TransportFraming;
      reporter.report_finding(*finding);
    }

    // Update status periodically
    auto totalElapsed = std::chrono::steady_clock::now() - startTime;
    auto elapsedSec = std::chrono::duration<double>(totalElapsed).count();
    auto rate = elapsedSec > 0 ? static_cast<double>(caseNum) / elapsedSec : 0.0;
    reporter.update_status(caseNum, rate, FuzzLayer::TransportFraming, monitor.server_alive());
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

  client.reset();
  fixture.stop();
}

}  // namespace fuzz
