// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "baseline.h"
#include "fuzz_client.h"

#include "ua_json_helpers.h"

#include "ua_application_configuration.h"
#include "ua_logger.h"
#include "ua_browse_request.h"
#include "ua_client.h"
#include "ua_crypto_types.h"
#include "ua_message_security_mode.h"
#include "ua_read_request.h"
#include "ua_server.h"
#include "ua_server_config_bundle.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_server_authentication.h"
#include <boost/asio/thread_pool.hpp>
#include <optional>
#include "ua_transport_address.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_write_request.h"

#include <boost/json.hpp>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <sstream>
#include <vector>

namespace fuzz
{

namespace
{

struct BaselineServerFixture
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
    appCfg.application_description_part().applicationUri = "urn:reduktive:opcua-sdk:fuzz:baseline";

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

LatencyStats compute_stats(std::vector<double>& samples)
{
  LatencyStats stats;
  if (samples.empty())
    return stats;

  std::sort(samples.begin(), samples.end());

  stats.minUs = samples.front();

  double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
  stats.meanUs = sum / static_cast<double>(samples.size());

  auto percentile = [&](double p) -> double
  {
    auto idx = static_cast<size_t>(p * static_cast<double>(samples.size() - 1));
    return samples[std::min(idx, samples.size() - 1)];
  };
  stats.p95Us = percentile(0.95);
  stats.p99Us = percentile(0.99);

  double sqSum = 0.0;
  for (auto v : samples)
  {
    double diff = v - stats.meanUs;
    sqSum += diff * diff;
  }
  stats.stddevUs = std::sqrt(sqSum / static_cast<double>(samples.size()));

  return stats;
}

std::vector<double> measure_service_latency(
  ua::client::Session& session, const std::string& serviceName, uint32_t samples)
{
  std::vector<double> latencies;
  latencies.reserve(samples);

  for (uint32_t i = 0; i < samples; ++i)
  {
    auto start = std::chrono::steady_clock::now();

    if (serviceName == "Read")
    {
      ua::ReadRequest req;
      ua::ReadValueId rv;
      rv.node_id() = ua::NodeId(0, 2258);  // Server_ServerStatus_CurrentTime
      rv.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
      req.nodes_to_read().push_back(std::move(rv));
      auto resp = session.attributes().try_read_sync(std::move(req));
      (void)resp;
    }
    else if (serviceName == "Browse")
    {
      ua::BrowseRequest req;
      ua::BrowseDescription bd;
      bd.node_id() = ua::NodeId(0, 85);  // Objects folder
      bd.browse_direction() = ua::BrowseDirection::Forward;
      bd.result_mask() = 63;
      req.nodes_to_browse().push_back(std::move(bd));
      req.requested_max_references_per_node() = 10;
      auto resp = session.view().try_browse_sync(std::move(req));
      (void)resp;
    }
    else if (serviceName == "Write")
    {
      ua::WriteRequest req;
      ua::WriteValue wv;
      wv.node_id() =
        ua::NodeId(0, 2258);  // Server_ServerStatus_CurrentTime (will fail, but we measure latency)
      wv.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
      ua::DataValue dv;
      dv.value() = ua::Variant(int32_t{42});
      wv.value() = std::move(dv);
      req.nodes_to_write().push_back(std::move(wv));
      auto resp = session.attributes().try_write_sync(std::move(req));
      (void)resp;
    }

    auto elapsed = std::chrono::steady_clock::now() - start;
    auto us = std::chrono::duration<double, std::micro>(elapsed).count();
    latencies.push_back(us);
  }

  return latencies;
}

std::vector<double> measure_handshake_timing(
  ua::client::Client& client, const std::string& endpointUrl, uint32_t samples, const ua::Logger& log)
{
  std::vector<double> latencies;
  latencies.reserve(samples);

  // Fewer samples for handshake since it's heavier.
  auto handshakeSamples = std::min(samples, 20u);

  for (uint32_t i = 0; i < handshakeSamples; ++i)
  {
    auto start = std::chrono::steady_clock::now();

    ua::client::CoreClient::OpenChannelConfig channelConfig;
    channelConfig.endpointUrl = endpointUrl;
    channelConfig.securityMode = ua::MessageSecurityMode::None;
    channelConfig.securityPolicyId = ua::SecurityPolicyId::None;

    try
    {
      auto ch = client.core().open_channel_sync(channelConfig);
      auto sess = ch.create_session_sync({});
      sess.activate_sync();

      auto elapsed = std::chrono::steady_clock::now() - start;
      auto us = std::chrono::duration<double, std::micro>(elapsed).count();
      latencies.push_back(us);

      sess.close_sync();
      ch.close_sync();
    }
    catch (const std::exception& e)
    {
      log.warning("Handshake sample {} failed: {}", i, e.what());
    }
  }

  return latencies;
}

std::string current_timestamp_iso8601()
{
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#ifdef _WIN32
  gmtime_s(&tm, &time);
#else
  gmtime_r(&time, &tm);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

}  // namespace

BaselineData run_baseline(const FuzzerConfig& config, const ua::Logger& logger)
{
  auto log = logger.with_category("baseline");

  log.info("Starting in-process server");

  BaselineServerFixture fixture;
  fixture.start();

  log.info("Server listening on {}", fixture.endpointUrl);
  log.info("Connecting client");

  // Optional so it can be destroyed BEFORE fixture.stop() joins the client pool: a live Client
  // holds outstanding work on that pool, and join() would wait on it forever.
  std::optional<ua::client::Client> client{std::in_place,
    ua::client::Client::create(fixture.clientPool.get_executor(),
      fuzz::make_insecure_client_config(),
      {.crypto = ua::create_default_crypto()})};

  ua::client::CoreClient::OpenChannelConfig channelConfig;
  channelConfig.endpointUrl = fixture.endpointUrl;
  channelConfig.securityMode = ua::MessageSecurityMode::None;
  channelConfig.securityPolicyId = ua::SecurityPolicyId::None;

  auto channel = client->core().open_channel_sync(channelConfig);
  auto session = channel.create_session_sync({});
  session.activate_sync();

  auto samples = config.baseline.samples;

  log.info("Session active, profiling with {} samples per service", samples);

  BaselineData baseline;
  baseline.recordedAt = current_timestamp_iso8601();
  baseline.serverEndpoint = fixture.endpointUrl;
  baseline.samplesPerService = samples;

  // Profile each service.
  std::vector<std::string> services = {"Read", "Browse", "Write"};

  for (const auto& svc : services)
  {
    log.info("Profiling {}...", svc);
    auto latencies = measure_service_latency(session, svc, samples);
    auto stats = compute_stats(latencies);

    ServiceBaseline sb;
    sb.latency = stats;
    sb.expectedStatus = 0;  // Good
    sb.alertThresholdUs = stats.p99Us * config.baseline.latencyAlertMul;
    sb.warnThresholdUs = stats.p99Us * config.baseline.latencyWarnMul;

    baseline.services[svc] = sb;

    log.info("  {}: mean={}us p95={}us p99={}us",
      svc,
      static_cast<int>(stats.meanUs),
      static_cast<int>(stats.p95Us),
      static_cast<int>(stats.p99Us));
  }

  // Profile handshake timing.
  log.info("Profiling handshake timing");

  try
  {
    session.close_sync();
    channel.close_sync();
  }
  catch (...)
  {}

  auto handshakeLatencies = measure_handshake_timing(*client, fixture.endpointUrl, samples, log);
  auto handshakeStats = compute_stats(handshakeLatencies);

  baseline.connection.handshakeMeanUs = handshakeStats.meanUs;
  baseline.connection.handshakeP99Us = handshakeStats.p99Us;

  log.info("Handshake: mean={}us p99={}us",
    static_cast<int>(handshakeStats.meanUs),
    static_cast<int>(handshakeStats.p99Us));

  // Save baseline.
  auto outputPath = config.reporting.outputDir + "/baseline.json";
  std::filesystem::create_directories(config.reporting.outputDir);
  save_baseline(baseline, outputPath);

  log.info("Baseline saved to {}", outputPath);

  client.reset();
  fixture.stop();

  return baseline;
}

std::optional<BaselineData> load_baseline(const std::string& path, const ua::Logger& logger)
{
  auto log = logger.with_category("baseline");

  std::ifstream file(path);
  if (!file.is_open())
    return std::nullopt;

  std::ostringstream ss;
  ss << file.rdbuf();

  try
  {
    auto jv = boost::json::parse(ss.str());
    auto& root = jv.as_object();

    BaselineData baseline;
    baseline.recordedAt = std::string(root.at("recorded_at").as_string());
    baseline.serverEndpoint = std::string(root.at("server_endpoint").as_string());
    baseline.samplesPerService = static_cast<uint32_t>(root.at("samples_per_service").as_int64());

    auto& services = root.at("services").as_object();
    for (auto& [key, val] : services)
    {
      auto& svcObj = val.as_object();
      ServiceBaseline sb;

      auto& lat = svcObj.at("latency_us").as_object();
      sb.latency.minUs = lat.at("min").to_number<double>();
      sb.latency.meanUs = lat.at("mean").to_number<double>();
      sb.latency.p95Us = lat.at("p95").to_number<double>();
      sb.latency.p99Us = lat.at("p99").to_number<double>();
      sb.latency.stddevUs = lat.at("stddev").to_number<double>();

      sb.expectedStatus = static_cast<uint32_t>(svcObj.at("expected_status").to_number<int64_t>());
      sb.alertThresholdUs = svcObj.at("alert_threshold_us").to_number<double>();
      sb.warnThresholdUs = svcObj.at("warn_threshold_us").to_number<double>();

      baseline.services[std::string(key)] = sb;
    }

    auto& conn = root.at("connection").as_object();
    baseline.connection.handshakeMeanUs = conn.at("handshake_mean_us").to_number<double>();
    baseline.connection.handshakeP99Us = conn.at("handshake_p99_us").to_number<double>();

    return baseline;
  }
  catch (const std::exception& e)
  {
    log.error("Failed to parse {}: {}", path, e.what());
    return std::nullopt;
  }
}

void save_baseline(const BaselineData& baseline, const std::string& path)
{
  boost::json::object root;
  root["recorded_at"] = baseline.recordedAt;
  root["server_endpoint"] = baseline.serverEndpoint;
  root["samples_per_service"] = baseline.samplesPerService;

  boost::json::object services;
  for (const auto& [name, sb] : baseline.services)
  {
    boost::json::object svcObj;

    boost::json::object lat;
    lat["min"] = sb.latency.minUs;
    lat["mean"] = sb.latency.meanUs;
    lat["p95"] = sb.latency.p95Us;
    lat["p99"] = sb.latency.p99Us;
    lat["stddev"] = sb.latency.stddevUs;
    svcObj["latency_us"] = std::move(lat);

    svcObj["expected_status"] = sb.expectedStatus;
    svcObj["alert_threshold_us"] = sb.alertThresholdUs;
    svcObj["warn_threshold_us"] = sb.warnThresholdUs;

    services[name] = std::move(svcObj);
  }
  root["services"] = std::move(services);

  boost::json::object conn;
  conn["handshake_mean_us"] = baseline.connection.handshakeMeanUs;
  conn["handshake_p99_us"] = baseline.connection.handshakeP99Us;
  root["connection"] = std::move(conn);

  std::ofstream out(path);
  out << ua::json_helpers::pretty_json(root);
}

}  // namespace fuzz
