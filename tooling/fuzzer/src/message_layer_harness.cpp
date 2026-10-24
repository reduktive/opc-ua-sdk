// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "message_layer_harness.h"
#include "fuzz_client.h"

#include "fuzz_security_policy.h"
#include "input_generators.h"
#include "mutation_engine.h"

#include "ua_logger.h"

#include "ua_application_configuration.h"
#include "ua_browse_request.h"
#include "ua_client.h"
#include "ua_client_test_hooks.h"
#include "ua_crypto_types.h"
#include "ua_message_security_mode.h"
#include "ua_read_request.h"
#include "ua_security_policy.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_server.h"
#include "ua_server_config_bundle.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_server_authentication.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_transport_address.h"
#include "ua_write_request.h"

#include <algorithm>
#include <chrono>
#include <mutex>

namespace fuzz
{

namespace
{

struct MessageServerFixture
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
    appCfg.application_description_part().applicationUri = "urn:reduktive:opcua-sdk:fuzz:message-layer";

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

/// Shared state for the mutation interceptor.
/// The FuzzSecurityPolicy callback captures this to communicate mutation info back.
struct InterceptorState
{
  std::mutex mutex;
  MutationEngine* engine{nullptr};
  bool mutateEnabled{false};
  MutationStrategy lastStrategy{MutationStrategy::BitFlip};
  std::vector<uint8_t> lastOriginalBytes;
  std::vector<uint8_t> lastMutatedBytes;
};

ua::client::ClientTestHooks make_message_fuzz_hooks(std::shared_ptr<InterceptorState> state)
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

        state->lastOriginalBytes = buffer;

        state->lastStrategy = state->engine->mutate(buffer);
        state->lastMutatedBytes = buffer;

        return ua::ByteString{std::move(buffer)};
      });

    return fuzzPolicy;
  };

  return hooks;
}

ua::client::CoreClient::OpenChannelConfig make_channel_config(const std::string& endpointUrl)
{
  ua::client::CoreClient::OpenChannelConfig channelConfig;
  channelConfig.endpointUrl = endpointUrl;
  channelConfig.securityMode = ua::MessageSecurityMode::None;
  channelConfig.securityPolicyId = ua::SecurityPolicyId::None;
  return channelConfig;
}

void run_fuzz_case(ua::client::Session& session, FuzzService service, ReadRequestGenerator& readGen,
  BrowseRequestGenerator& browseGen, WriteRequestGenerator& writeGen, std::mt19937_64& rng, Monitor& monitor,
  Reporter& reporter, std::shared_ptr<InterceptorState> state, uint64_t caseNum)
{
  Monitor::CaseOutcome outcome;
  outcome.caseNumber = caseNum;
  outcome.layer = FuzzLayer::MessageEncoding;
  outcome.service = service;

  // Enable mutation for this case
  {
    std::lock_guard lock(state->mutex);
    state->mutateEnabled = true;
    state->lastOriginalBytes.clear();
    state->lastMutatedBytes.clear();
  }

  auto start = std::chrono::steady_clock::now();
  try
  {
    switch (service)
    {
    case FuzzService::Read:
    {
      ua::ReadRequest req;
      auto numNodes = std::uniform_int_distribution<int>(1, 3)(rng);
      for (int i = 0; i < numNodes; ++i)
      {
        req.nodes_to_read().push_back(readGen.generate_read_value_id());
      }
      req.timestamps_to_return() = readGen.generate_timestamps_to_return();
      req.max_age() = static_cast<double>(readGen.generate_max_age());
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
      auto numNodes = std::uniform_int_distribution<int>(1, 3)(rng);
      for (int i = 0; i < numNodes; ++i)
      {
        req.nodes_to_browse().push_back(browseGen.generate_browse_description());
      }
      req.requested_max_references_per_node() = browseGen.generate_requested_max_references_per_node();
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
      auto numNodes = std::uniform_int_distribution<int>(1, 3)(rng);
      for (int i = 0; i < numNodes; ++i)
      {
        req.nodes_to_write().push_back(writeGen.generate_write_value());
      }
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
  }
  catch (...)
  {
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

  // Disable mutation
  {
    std::lock_guard lock(state->mutex);
    state->mutateEnabled = false;
  }

  // A mutation can leave the request intact and add bytes after it: BlockDuplicate appends a copy
  // of a block beyond the chunk's MessageSize. The server answers the request and closes the
  // channel on the bytes that follow, and which of the two reaches the client first is a race, so a
  // Good response does not show that the server accepted the mutated chunk. An unmutated Read sent
  // after the case does: the server reads the stream in order, so the Read is answered only if the
  // channel survived everything the case sent.
  if (!outcome.exceptionThrown && (outcome.statusCode & 0xC0000000u) == 0u)
  {
    ua::ReadRequest probe;
    ua::ReadValueId rv;
    rv.node_id() = ua::NodeId{0, 2255};  // Server_ServerStatus
    rv.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
    probe.nodes_to_read().push_back(std::move(rv));
    auto probeResp = session.attributes().try_read_sync(std::move(probe));
    if (!probeResp.is_good())
    {
      outcome.statusCode = probeResp.status_code().as_uint32();
    }
  }

  if (auto finding = monitor.record(outcome))
  {
    // Attach the mutated bytes as trigger data
    {
      std::lock_guard lock(state->mutex);
      finding->triggerBytes = state->lastMutatedBytes;
      finding->strategy = state->lastStrategy;
    }
    finding->layer = FuzzLayer::MessageEncoding;
    reporter.report_finding(*finding);
  }
}

}  // namespace

void run_message_layer_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger)
{
  auto log = logger.with_category("message");
  log.info("Starting in-process server");

  MessageServerFixture fixture;
  fixture.start();

  log.info("Server listening on {}", fixture.endpointUrl);
  log.info("Connecting client with FuzzSecurityPolicy");

  auto state = std::make_shared<InterceptorState>();
  MutationEngine mutationEngine(config.campaign.rngSeed);
  state->engine = &mutationEngine;

  // Scope the client-side objects so they are destroyed before fixture.stop() joins
  // clientPool; a live client keeps outstanding work on that pool and join() would
  // otherwise block forever (teardown hang).
  {
    auto client = ua::client::Client::create(fixture.clientPool.get_executor(),
      fuzz::make_insecure_client_config(),
      {.crypto = ua::create_default_crypto()});
    ua::client::CoreClientTestAccess::set_test_hooks(client.core(), make_message_fuzz_hooks(state));
    auto channelConfig = make_channel_config(fixture.endpointUrl);

    auto channel = client.core().open_channel_sync(channelConfig);
    auto session = channel.create_session_sync({});
    session.activate_sync();

    log.info("Session active, starting fuzz loop");

    std::mt19937_64 rng(config.campaign.rngSeed != 0 ? config.campaign.rngSeed : std::random_device{}());

    ReadRequestGenerator readGen(rng, config.limits);
    BrowseRequestGenerator browseGen(rng, config.limits);
    WriteRequestGenerator writeGen(rng, config.limits);

    const FuzzService services[] = {FuzzService::Read, FuzzService::Browse, FuzzService::Write};

    auto maxCases = config.campaign.maxCases;
    auto startTime = std::chrono::steady_clock::now();

    for (uint64_t caseNum = 1; maxCases == 0 || caseNum <= maxCases; ++caseNum)
    {
      auto serviceChoice = std::uniform_int_distribution<int>(0, 2)(rng);
      auto service = services[serviceChoice];

      run_fuzz_case(session, service, readGen, browseGen, writeGen, rng, monitor, reporter, state, caseNum);

      // Update status periodically
      auto elapsed = std::chrono::steady_clock::now() - startTime;
      auto elapsedSec = std::chrono::duration<double>(elapsed).count();
      auto rate = elapsedSec > 0 ? static_cast<double>(caseNum) / elapsedSec : 0.0;
      reporter.update_status(caseNum, rate, FuzzLayer::MessageEncoding, monitor.server_alive());

      // If server connection lost, reconnect with fresh interceptor
      if (!monitor.server_alive())
      {
        log.warning("Server connection lost, attempting reconnect");
        try
        {
          channelConfig = make_channel_config(fixture.endpointUrl);
          channel = client.core().open_channel_sync(channelConfig);
          session = channel.create_session_sync({});
          session.activate_sync();
          monitor.set_server_alive(true);
          log.info("Reconnected");
        }
        catch (const std::exception& e)
        {
          log.error("Reconnect failed: {}", e.what());
          break;
        }
      }
    }

    auto totalElapsed = std::chrono::steady_clock::now() - startTime;
    auto totalSec = std::chrono::duration<double>(totalElapsed).count();

    log.info("Fuzz loop complete");

    FuzzResult result;
    result.totalCases = maxCases;
    result.acceptedMutations = monitor.accepted_mutations();
    result.rejectedMutations = monitor.rejected_mutations();
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

    try
    {
      session.close_sync();
      channel.close_sync();
    }
    catch (...)
    {}
  }  // client/channel/session destroyed here, releasing all clientPool work

  fixture.stop();
}

}  // namespace fuzz
