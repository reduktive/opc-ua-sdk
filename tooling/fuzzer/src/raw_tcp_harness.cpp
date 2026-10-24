// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "raw_tcp_harness.h"
#include "fuzz_client.h"

#include "mutation_engine.h"

#include "ua_application_configuration.h"
#include "ua_logger.h"
#include "ua_client.h"
#include "ua_crypto_types.h"
#include "ua_message_security_mode.h"
#include "ua_read_request.h"
#include "ua_session_attribute_services.h"
#include "ua_server.h"
#include "ua_server_config_bundle.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_server_authentication.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_transport_address.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>

#include <chrono>
#include <cstring>
#include <random>
#include <string>

namespace fuzz
{

namespace
{

struct RawTcpServerFixture
{
  boost::asio::thread_pool serverPool;
  boost::asio::thread_pool clientPool;
  std::optional<ua::server::Server> server;
  std::string endpointUrl;
  std::string host;
  uint16_t port{0};
  ua::server::ListenerHandle listener{0};

  void start()
  {
    auto appCfg = ua::ApplicationConfig::load_default();
    appCfg.allowInsecureEndpoints = true;
    // Required: published as Server.ServerArray[0] and as the URI of the server's own namespace.
    appCfg.application_description_part().applicationUri = "urn:reduktive:opcua-sdk:fuzz:raw-tcp";

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

    // Parse host:port from opc.tcp://host:port
    auto url = endpointUrl;
    auto prefix = std::string("opc.tcp://");
    if (url.substr(0, prefix.size()) == prefix)
    {
      url = url.substr(prefix.size());
    }
    auto colonPos = url.rfind(':');
    if (colonPos != std::string::npos)
    {
      host = url.substr(0, colonPos);
      port = static_cast<uint16_t>(std::stoi(url.substr(colonPos + 1)));
    }
  }

  void stop()
  {
    server.reset();
    clientPool.join();
    serverPool.join();
  }
};

/// Generate raw fuzz data based on scenario
enum class RawScenario
{
  /// Completely random bytes
  RandomBytes,
  /// Protocol-shaped noise: starts with valid-ish message header, garbage body
  ProtocolShaped,
  /// HTTP request (common misdirected traffic)
  HttpRequest,
  /// TLS ClientHello prefix
  TlsClientHello,
  /// Empty connection (connect then immediately close)
  EmptyConnect,
  /// Very large payload
  LargePayload,
  /// Valid HEL message, heavily mutated
  MutatedHel,
};

std::vector<uint8_t> generate_random_bytes(std::mt19937_64& rng, size_t minLen, size_t maxLen)
{
  auto len = std::uniform_int_distribution<size_t>(minLen, maxLen)(rng);
  std::vector<uint8_t> buf(len);
  for (auto& b : buf)
  {
    b = static_cast<uint8_t>(std::uniform_int_distribution<int>(0, 255)(rng));
  }
  return buf;
}

std::vector<uint8_t> generate_protocol_shaped(std::mt19937_64& rng)
{
  // OPC UA message header: 3-byte type + 'F', 4-byte LE size, then garbage
  const char* types[] = {"HEL", "ACK", "MSG", "OPN", "CLO", "ERR"};
  auto typeIdx = std::uniform_int_distribution<int>(0, 5)(rng);

  std::vector<uint8_t> buf;
  buf.push_back(static_cast<uint8_t>(types[typeIdx][0]));
  buf.push_back(static_cast<uint8_t>(types[typeIdx][1]));
  buf.push_back(static_cast<uint8_t>(types[typeIdx][2]));
  buf.push_back('F');

  // Message size (random, possibly wrong)
  auto bodyLen = std::uniform_int_distribution<int>(0, 1024)(rng);
  uint32_t msgSize = static_cast<uint32_t>(8 + bodyLen);
  buf.push_back(static_cast<uint8_t>(msgSize & 0xFF));
  buf.push_back(static_cast<uint8_t>((msgSize >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>((msgSize >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((msgSize >> 24) & 0xFF));

  // Random body
  for (int i = 0; i < bodyLen; ++i)
  {
    buf.push_back(static_cast<uint8_t>(std::uniform_int_distribution<int>(0, 255)(rng)));
  }
  return buf;
}

std::vector<uint8_t> generate_http_request()
{
  const char* req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
  return std::vector<uint8_t>(req, req + std::strlen(req));
}

std::vector<uint8_t> generate_tls_client_hello(std::mt19937_64& rng)
{
  // TLS record header + ClientHello prefix
  std::vector<uint8_t> buf = {
    0x16,  // ContentType: Handshake
    0x03,
    0x01,  // TLS 1.0
    0x00,
    0x50,  // Length (80 bytes)
    0x01,  // HandshakeType: ClientHello
    0x00,
    0x00,
    0x4C,  // Length
    0x03,
    0x03,  // TLS 1.2
  };
  // Fill rest with random
  for (int i = 0; i < 72; ++i)
  {
    buf.push_back(static_cast<uint8_t>(std::uniform_int_distribution<int>(0, 255)(rng)));
  }
  return buf;
}

std::vector<uint8_t> generate_valid_hel(const std::string& endpointUrl)
{
  // OPC UA HEL message
  // Header: "HELF" + uint32 size
  // Body: uint32 protocolVersion, uint32 receiveBufferSize, uint32 sendBufferSize,
  //       uint32 maxMessageSize, uint32 maxChunkCount, int32 urlLen, url bytes
  uint32_t urlLen = static_cast<uint32_t>(endpointUrl.size());
  uint32_t bodySize = 5 * 4 + 4 + urlLen;  // 5 uint32s + string length prefix + string
  uint32_t msgSize = 8 + bodySize;

  std::vector<uint8_t> buf;
  buf.reserve(msgSize);

  // Header
  buf.push_back('H');
  buf.push_back('E');
  buf.push_back('L');
  buf.push_back('F');

  auto pushU32 = [&buf](uint32_t v)
  {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
  };

  pushU32(msgSize);

  // Body
  pushU32(0);  // protocolVersion
  pushU32(65535);  // receiveBufferSize
  pushU32(65535);  // sendBufferSize
  pushU32(0);  // maxMessageSize (0 = no limit)
  pushU32(0);  // maxChunkCount (0 = no limit)
  pushU32(urlLen);  // string length

  for (char c : endpointUrl)
  {
    buf.push_back(static_cast<uint8_t>(c));
  }

  return buf;
}

}  // namespace

void run_raw_tcp_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger)
{
  auto log = logger.with_category("raw");
  log.info("Starting in-process server");

  RawTcpServerFixture fixture;
  fixture.start();

  log.info("Server listening on {} ({}:{})", fixture.endpointUrl, fixture.host, fixture.port);
  log.info("Starting raw TCP fuzz loop");

  std::mt19937_64 rng(config.campaign.rngSeed != 0 ? config.campaign.rngSeed : std::random_device{}());
  MutationEngine mutationEngine(config.campaign.rngSeed);

  constexpr int numScenarios = 7;
  const RawScenario scenarios[] = {
    RawScenario::RandomBytes,
    RawScenario::ProtocolShaped,
    RawScenario::HttpRequest,
    RawScenario::TlsClientHello,
    RawScenario::EmptyConnect,
    RawScenario::LargePayload,
    RawScenario::MutatedHel,
  };

  auto maxCases = config.campaign.maxCases;
  auto startTime = std::chrono::steady_clock::now();

  boost::asio::io_context ioc;

  for (uint64_t caseNum = 1; maxCases == 0 || caseNum <= maxCases; ++caseNum)
  {
    Monitor::CaseOutcome outcome;
    outcome.caseNumber = caseNum;
    outcome.layer = FuzzLayer::Raw;
    outcome.service = FuzzService::GetEndpoints;

    auto scenarioIdx = std::uniform_int_distribution<int>(0, numScenarios - 1)(rng);
    auto scenario = scenarios[scenarioIdx];

    auto caseStart = std::chrono::steady_clock::now();
    std::vector<uint8_t> sentBytes;

    try
    {
      boost::asio::ip::tcp::socket socket(ioc);
      boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address(fixture.host), fixture.port);
      socket.connect(ep);

      if (scenario != RawScenario::EmptyConnect)
      {
        switch (scenario)
        {
        case RawScenario::RandomBytes:
          sentBytes = generate_random_bytes(rng, 1, 512);
          break;
        case RawScenario::ProtocolShaped:
          sentBytes = generate_protocol_shaped(rng);
          break;
        case RawScenario::HttpRequest:
          sentBytes = generate_http_request();
          break;
        case RawScenario::TlsClientHello:
          sentBytes = generate_tls_client_hello(rng);
          break;
        case RawScenario::LargePayload:
          sentBytes = generate_random_bytes(rng, 8192, 65536);
          break;
        case RawScenario::MutatedHel:
        {
          sentBytes = generate_valid_hel(fixture.endpointUrl);
          mutationEngine.mutate(sentBytes);
          break;
        }
        default:
          break;
        }

        boost::asio::write(socket, boost::asio::buffer(sentBytes.data(), sentBytes.size()));
      }

      // Half-close the send side to signal EOF to the server.
      boost::system::error_code ec;
      socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

      // Try to read a response (non-blocking, best effort)
      std::vector<uint8_t> readBuf(4096);
      socket.non_blocking(true);
      socket.read_some(boost::asio::buffer(readBuf), ec);

      socket.close(ec);
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

    auto elapsed = std::chrono::steady_clock::now() - caseStart;
    outcome.latency = std::chrono::duration_cast<std::chrono::microseconds>(elapsed);

    if (auto finding = monitor.record(outcome))
    {
      finding->triggerBytes = sentBytes;
      finding->layer = FuzzLayer::Raw;
      reporter.report_finding(*finding);
    }

    auto totalElapsed = std::chrono::steady_clock::now() - startTime;
    auto elapsedSec = std::chrono::duration<double>(totalElapsed).count();
    auto rate = elapsedSec > 0 ? static_cast<double>(caseNum) / elapsedSec : 0.0;
    reporter.update_status(caseNum, rate, FuzzLayer::Raw, monitor.server_alive());
  }

  auto totalElapsed = std::chrono::steady_clock::now() - startTime;
  auto totalSec = std::chrono::duration<double>(totalElapsed).count();

  log.info("Fuzz loop complete");

  // Health check: verify server still works after raw fuzzing
  log.info("Health check: connecting with SDK client");
  bool healthOk = false;
  try
  {
    auto client = ua::client::Client::create(fixture.clientPool.get_executor(),
      fuzz::make_insecure_client_config(),
      {.crypto = ua::create_default_crypto()});
    ua::client::CoreClient::OpenChannelConfig channelConfig;
    channelConfig.endpointUrl = fixture.endpointUrl;
    channelConfig.securityMode = ua::MessageSecurityMode::None;
    channelConfig.securityPolicyId = ua::SecurityPolicyId::None;

    auto channel = client.core().open_channel_sync(channelConfig);
    auto session = channel.create_session_sync({});
    session.activate_sync();

    ua::ReadRequest req;
    ua::ReadValueId rv;
    rv.node_id() = ua::NodeId{0, 2255};
    rv.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    auto resp = session.attributes().try_read_sync(std::move(req));
    healthOk = resp.is_good();

    session.close_sync();
    channel.close_sync();
  }
  catch (const std::exception& e)
  {
    log.error("Health check failed: {}", e.what());
  }

  if (healthOk)
  {
    log.info("Health check passed");
  }
  else
  {
    log.warning("Health check failed - server may be degraded");
  }

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

  fixture.stop();
}

}  // namespace fuzz
