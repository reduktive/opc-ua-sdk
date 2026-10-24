// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "perf_tester.h"
#include "fuzz_client.h"

#include "baseline.h"
#include "ua_json_helpers.h"

#include "ua_application_configuration.h"
#include "ua_logger.h"
#include "ua_status_to_string.h"
#include "ua_data_change_notification.h"
#include "ua_access_level_type.h"
#include "ua_datatype_id.h"
#include "ua_node_accessor.h"
#include "ua_value_rank.h"
#include "ua_role_configuration.h"
#include "ua_browse_request.h"
#include "ua_client.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_crypto_types.h"
#include "ua_delete_monitored_items_request.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_message_security_mode.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitoring_parameters.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_server.h"
#include "ua_server_config_bundle.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_server_authentication.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_transport_address.h"
#include "static_array_namespace.h"
#include "ua_session_attribute_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_address_space.h"
#include "ua_node_accessor.h"
#include "ua_session_view_services.h"
#include "ua_write_request.h"

#include <boost/json.hpp>
#include <algorithm>
#include <atomic>
#include <csignal>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

namespace fuzz
{

namespace
{

/// Numeric id of the first generated node, and how many exist. Generated nodes live
/// in namespace 1 so they cannot collide with NS0.
uint16_t gGeneratedNodeNs = 1;
constexpr uint32_t generatedNodeBase = 60000;
uint32_t gGeneratedNodeCount = 0;
uint32_t gNodesPerRead = 1;

struct PerfServerFixture
{
  /// @param serverThreads  Size of the server executor pool; 0 means hardware_concurrency().
  /// @param attachUrl      When set, no server is started here: the fixture hands out
  ///                       clients pointed at an already-running server, so the load
  ///                       generator can sit on a different machine from the server.
  /// @param listenAddress  Bind address used when this fixture does start a server.
  explicit PerfServerFixture(uint32_t serverThreads, std::string attachUrl = {},
    std::string listenAddress = "127.0.0.1:0", bool relaxThrottling = false, uint32_t throttleMaxConns = 0,
    uint32_t throttleAttemptsPerMin = 0, uint32_t maxConnections = 0, uint32_t maxSecureChannels = 0,
    uint32_t maxSessions = 0, uint32_t generateNodes = 0, uint32_t maxMonitoredItems = 0,
    uint32_t maxMonitoredItemsPerSub = 0, uint32_t maxMonitoredItemsPerCall = 0)
    : serverPool(
        attachUrl.empty()
          ? (serverThreads > 0 ? static_cast<std::size_t>(serverThreads)
                               : static_cast<std::size_t>(std::max(1u, std::thread::hardware_concurrency())))
          : std::size_t{1}),
      serverThreads(serverThreads > 0 ? serverThreads : std::max(1u, std::thread::hardware_concurrency())),
      attachUrl(std::move(attachUrl)), listenAddress(std::move(listenAddress)),
      relaxThrottling(relaxThrottling), throttleMaxConns(throttleMaxConns),
      throttleAttemptsPerMin(throttleAttemptsPerMin), maxConnections(maxConnections),
      maxSecureChannels(maxSecureChannels), maxSessions(maxSessions), generateNodes(generateNodes),
      maxMonitoredItems(maxMonitoredItems), maxMonitoredItemsPerSub(maxMonitoredItemsPerSub),
      maxMonitoredItemsPerCall(maxMonitoredItemsPerCall)
  {}

  boost::asio::thread_pool serverPool;
  boost::asio::thread_pool clientPool;
  uint32_t serverThreads{0};
  std::string attachUrl;
  std::string listenAddress;
  bool relaxThrottling{false};
  uint32_t throttleMaxConns{0};
  uint32_t throttleAttemptsPerMin{0};
  uint32_t maxConnections{0};
  uint32_t maxSecureChannels{0};
  uint32_t maxSessions{0};
  uint32_t generateNodes{0};
  uint32_t generatedNodes{0};
  /// 0 = default namespace, 1 = static array per-node, 2 = static array all-on-one-node.
  uint32_t staticNamespace{0};
  uint32_t maxMonitoredItems{0};
  uint32_t maxMonitoredItemsPerSub{0};
  uint32_t maxMonitoredItemsPerCall{0};
  std::optional<ua::server::Server> server;
  std::string endpointUrl;
  ua::server::ListenerHandle listener{0};

  /// True when the server under test is somewhere else, so nothing here describes it.
  bool attached() const
  {
    return !attachUrl.empty();
  }

  /// Populate namespace 1 with simple scalar Int32 variables.
  ///
  /// Stored scalars with CurrentRead access and no external value source, so a Read
  /// of one costs the request path and nothing else. Created through the ordinary
  /// public address-space API, so they are no more privileged than a licensee's own
  /// nodes would be.
  void generate_nodes()
  {
    if (generateNodes == 0)
      return;

    auto addressSpace = server->address_space();

    if (staticNamespace != 0)
    {
      // A lock-free array of immutable scalars in place of the default namespace, so a read costs
      // three integer comparisons and a dereference. See static_array_namespace.h for what this is
      // measuring and why. The index it lands at is NOT 1 - the server already owns that - so it is
      // logged, and the generator is told with --read-ns.
      const auto sharing = (staticNamespace == 2) ? fuzz::StaticArrayNamespace::Sharing::OneNode
                                                  : fuzz::StaticArrayNamespace::Sharing::PerNode;
      auto staticNs = std::make_shared<fuzz::StaticArrayNamespace>(
        "urn:reduktive:perf:static", generateNodes, generatedNodeBase, sharing);
      const auto index = addressSpace.add_namespace_sync(staticNs);
      gGeneratedNodeNs = index;
      generatedNodes = generateNodes;
      gGeneratedNodeCount = generateNodes;
      std::cout << "[perf-serve] static array namespace at ns=" << index << " with " << generateNodes
                << " immutable scalars, sharing=" << (staticNamespace == 2 ? "one-node" : "per-node")
                << " - drive it with --read-ns " << index << "\n"
                << std::flush;
      return;
    }

    const ua::AccessLevelType readOnly{ua::AccessLevelType::Bit::CurrentRead};
    uint32_t created = 0;

    for (uint32_t i = 0; i < generateNodes; ++i)
    {
      const ua::NodeId nodeId{gGeneratedNodeNs, generatedNodeBase + i};
      auto result = addressSpace.try_create_node_sync(nodeId, ua::NodeClass::Variable);
      if (result.is_bad())
        continue;

      auto variable = result.value().as<ua::VariableAccessor>();
      if (!variable)
        continue;

      const auto name = "PerfVar" + std::to_string(i);
      variable->set_browse_name(ua::QualifiedName{gGeneratedNodeNs, name});
      variable->set_display_name(ua::LocalizedText{"", name});
      variable->set_data_type(ua::NodeId{ua::DataTypeId::Int32});
      variable->set_value_rank(ua::ValueRank{ua::ValueRank::scalar});
      variable->set_access_level(readOnly);
      variable->write_value_sync(static_cast<int32_t>(i));
      ++created;
    }
    generatedNodes = created;
    gGeneratedNodeCount = created;
  }

  void start()
  {
    if (attached())
    {
      endpointUrl = attachUrl;
      return;
    }

    auto appCfg = ua::ApplicationConfig::load_default();
    appCfg.allowInsecureEndpoints = true;
    // Required: published as Server.ServerArray[0] and as the URI of the server's own namespace.
    appCfg.application_description_part().applicationUri = "urn:reduktive:opcua-sdk:fuzz:perf";

    ua::server::ServerConfig serverCfg{};
    if (relaxThrottling)
    {
      // Every connection arrives from the load generator's single address, so the
      // per-IP throttle would stop the run long before the server ran out of capacity.
      serverCfg.connectionThrottling.maxConnectionsPerEndpoint = 100000;
      serverCfg.connectionThrottling.maxConnectionAttemptsPerMinute = 1000000;
    }

    // Explicit overrides win, so one limit can be raised while the other is held
    // at its default and the refusal attributed to a single gate.
    if (throttleMaxConns > 0)
      serverCfg.connectionThrottling.maxConnectionsPerEndpoint = throttleMaxConns;
    if (throttleAttemptsPerMin > 0)
      serverCfg.connectionThrottling.maxConnectionAttemptsPerMinute = throttleAttemptsPerMin;

    // MaxConnections and MaxSecureChannels are consecutive admission gates, and the
    // transport-level one must sit above the channel-level one or it refuses first.
    if (maxSecureChannels > 0)
      serverCfg.maxSecureChannels = maxSecureChannels;
    if (maxConnections > 0)
      serverCfg.maxConnections = maxConnections;
    if (maxSessions > 0)
      serverCfg.server_capabilities().maxSessions = maxSessions;
    if (maxMonitoredItems > 0)
      serverCfg.server_capabilities().maxMonitoredItems = maxMonitoredItems;
    if (maxMonitoredItemsPerSub > 0)
      serverCfg.server_capabilities().maxMonitoredItemsPerSubscription = maxMonitoredItemsPerSub;
    if (maxMonitoredItemsPerCall > 0)
      serverCfg.server_capabilities().operationLimits.maxMonitoredItemsPerCall = maxMonitoredItemsPerCall;

    ua::server::CreateConfig createCfg{.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};

    ua::server::ServerComponents components;
    components.crypto = ua::create_default_crypto();
    components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();
    // Without a Role grant the anonymous Session holds no read permission and every
    // Read comes back BadUserAccessDenied, so the load generator measures the cost
    // of a refusal rather than of a Read. Observer is the least privilege that makes
    // the measured operation the one being claimed.
    components.roleConfiguration = ua::server::RoleConfiguration::from_well_known_grants(
      {{ua::server::WellKnownRole::Observer, ua::IdentityCriteriaType::Anonymous}});

    server.emplace(
      ua::server::Server::create(serverPool.get_executor(), std::move(createCfg), std::move(components)));

    ua::server::ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = ua::MessageSecurityMode::None;
    endpoint.securityPolicyId = ua::SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));

    ua::transport::BindAddress bind;
    bind.address = listenAddress;

    listener = server->listen_sync(std::move(bind), {});
    server->add_endpoint(listener, endpoint);
    server->start_sync();

    generate_nodes();

    auto urls = server->advertised_urls(listener);
    endpointUrl = urls.front().str();
  }

  ua::client::Client make_client()
  {
    return ua::client::Client::create(clientPool.get_executor(),
      fuzz::make_insecure_client_config(),
      {.crypto = ua::create_default_crypto()});
  }

  ua::client::CoreClient::OpenChannelConfig channel_config()
  {
    ua::client::CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = endpointUrl;
    cfg.securityMode = ua::MessageSecurityMode::None;
    cfg.securityPolicyId = ua::SecurityPolicyId::None;
    return cfg;
  }

  void stop()
  {
    server.reset();
    clientPool.join();
    serverPool.join();
  }
};

struct LatencyStats
{
  double minUs{0.0};
  double meanUs{0.0};
  double p50Us{0.0};
  double p95Us{0.0};
  double p99Us{0.0};
  double p999Us{0.0};
  double maxUs{0.0};
  double stddevUs{0.0};
};

LatencyStats compute_stats(std::vector<double>& samples)
{
  LatencyStats stats;
  if (samples.empty())
    return stats;

  std::sort(samples.begin(), samples.end());

  stats.minUs = samples.front();
  stats.maxUs = samples.back();

  double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
  stats.meanUs = sum / static_cast<double>(samples.size());

  auto percentile = [&](double p) -> double
  {
    auto idx = static_cast<size_t>(p * static_cast<double>(samples.size() - 1));
    return samples[std::min(idx, samples.size() - 1)];
  };

  stats.p50Us = percentile(0.50);
  stats.p95Us = percentile(0.95);
  stats.p99Us = percentile(0.99);
  stats.p999Us = percentile(0.999);

  double sqSum = 0.0;
  for (auto v : samples)
  {
    double diff = v - stats.meanUs;
    sqSum += diff * diff;
  }
  stats.stddevUs = std::sqrt(sqSum / static_cast<double>(samples.size()));

  return stats;
}

/// One Read call: how long it took, and whether the service accepted it.
struct ReadOutcome
{
  double serviceUs{0.0};
  bool ok{false};
  /// Why it failed, so a refusal can be named rather than merely counted.
  ua::StatusCode status{};
};

/// Issue one Read and report both the elapsed time and the service result.
///
/// A refused request completes fast, so counting it as a normal sample pulls the
/// distribution down exactly where the server is under most pressure. Callers
/// keep the two apart: the sample goes in the histogram, the refusal in the
/// error tally.
/// Node under measurement. Set once from config before any load is applied.
ua::NodeId gReadNodeId{0, 2258};

/// Numeric ids assigned round-robin, one per session, when configured.
std::vector<uint32_t> gReadNodePool;

ReadOutcome issue_read(ua::client::Session& session, const ua::NodeId& node)
{
  ua::ReadRequest req;
  if (gGeneratedNodeCount > 0 && gNodesPerRead > 1)
  {
    // Batch across the generated pool, starting from this session's own node so
    // concurrent sessions do not all walk the pool in lockstep.
    const uint32_t start = (node.namespace_index() == gGeneratedNodeNs)
                             ? (node.identifier().get_numeric() - generatedNodeBase)
                             : 0U;
    for (uint32_t k = 0; k < gNodesPerRead; ++k)
    {
      ua::ReadValueId rv;
      rv.node_id() = ua::NodeId(gGeneratedNodeNs, generatedNodeBase + ((start + k) % gGeneratedNodeCount));
      rv.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
      req.nodes_to_read().push_back(std::move(rv));
    }
  }
  else
  {
    ua::ReadValueId rv;
    rv.node_id() = node;
    rv.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
  }

  auto start = std::chrono::steady_clock::now();
  auto resp = session.attributes().try_read_sync(std::move(req));
  auto elapsed = std::chrono::steady_clock::now() - start;

  ReadOutcome outcome;
  outcome.serviceUs = std::chrono::duration<double, std::micro>(elapsed).count();
  outcome.ok = static_cast<bool>(resp) && resp.value().response_header().service_result().is_good();
  if (!outcome.ok && static_cast<bool>(resp))
  {
    outcome.status = resp.value().response_header().service_result();
  }
  if (outcome.ok)
  {
    const auto& results = resp.value().results();
    outcome.ok = !results.empty();
    for (const auto& dv : results)
    {
      if (dv.status().has_value() && dv.status()->is_not_good())
      {
        outcome.ok = false;
        outcome.status = *dv.status();
        break;
      }
    }
  }
  return outcome;
}

ReadOutcome issue_read(ua::client::Session& session)
{
  return issue_read(session, gReadNodeId);
}

double measure_read_latency(ua::client::Session& session)
{
  return issue_read(session).serviceUs;
}

/// Read a single-line pseudo-file, trimmed. Returns an empty string when the
/// path is absent, so a non-Linux or restricted host degrades instead of failing.
std::string read_line_file(const char* path)
{
  std::ifstream in(path);
  std::string line;
  if (!std::getline(in, line))
    return {};
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
    line.pop_back();
  return line;
}

/// Record the conditions the numbers were taken under.
///
/// A throughput or percentile figure is only meaningful next to the machine that
/// produced it, so the summary carries the host, kernel, CPU and frequency
/// governor alongside the measurements rather than leaving them to be
/// remembered separately.
boost::json::object describe_host(uint32_t serverThreads)
{
  boost::json::object host;
  host["hostname"] = read_line_file("/proc/sys/kernel/hostname");
  host["kernel"] = read_line_file("/proc/sys/kernel/osrelease");
  host["scaling_governor"] = read_line_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
  host["hardware_concurrency"] = std::thread::hardware_concurrency();
  host["server_threads"] = serverThreads;

  std::ifstream cpuinfo("/proc/cpuinfo");
  std::string line;
  while (std::getline(cpuinfo, line))
  {
    if (line.rfind("model name", 0) == 0)
    {
      auto colon = line.find(':');
      if (colon != std::string::npos)
      {
        auto model = line.substr(colon + 1);
        while (!model.empty() && model.front() == ' ')
          model.erase(model.begin());
        host["cpu"] = model;
      }
      break;
    }
  }
  return host;
}

/// Read the current process resident set size (RSS) in kiB from
/// /proc/self/status. Returns std::nullopt if the value cannot be read so the
/// caller can skip the sample gracefully. Linux-only; CI soak runs on Linux.
std::optional<uint64_t> read_self_rss_kib()
{
  std::ifstream status("/proc/self/status");
  if (!status)
    return std::nullopt;

  std::string line;
  while (std::getline(status, line))
  {
    constexpr std::string_view prefix = "VmRSS:";
    if (line.compare(0, prefix.size(), prefix) == 0)
    {
      std::istringstream parser(line.substr(prefix.size()));
      uint64_t rssKib = 0;
      if (parser >> rssKib)
        return rssKib;
      return std::nullopt;
    }
  }
  return std::nullopt;
}

/// Count the number of open file descriptors for the current process by
/// enumerating /proc/self/fd (excluding "." and ".."). Returns std::nullopt on
/// failure so the caller can skip the sample gracefully.
std::optional<uint64_t> count_open_fds()
{
  std::error_code ec;
  std::filesystem::directory_iterator it("/proc/self/fd", ec);
  if (ec)
    return std::nullopt;

  uint64_t count = 0;
  for (const auto& entry : it)
  {
    (void)entry;
    ++count;
  }
  return count;
}

/// Least-squares slope of y vs x. Both vectors must be the same size with at
/// least two points; otherwise returns 0.0.
double least_squares_slope(const std::vector<double>& xs, const std::vector<double>& ys)
{
  if (xs.size() != ys.size() || xs.size() < 2)
    return 0.0;

  auto n = static_cast<double>(xs.size());
  double sumX = std::accumulate(xs.begin(), xs.end(), 0.0);
  double sumY = std::accumulate(ys.begin(), ys.end(), 0.0);
  double sumXX = 0.0;
  double sumXY = 0.0;
  for (size_t i = 0; i < xs.size(); ++i)
  {
    sumXX += xs[i] * xs[i];
    sumXY += xs[i] * ys[i];
  }

  double denom = n * sumXX - sumX * sumX;
  if (denom == 0.0)
    return 0.0;
  return (n * sumXY - sumX * sumY) / denom;
}

boost::json::object stats_to_json(const LatencyStats& s)
{
  boost::json::object o;
  o["min_us"] = s.minUs;
  o["mean_us"] = s.meanUs;
  o["p50_us"] = s.p50Us;
  o["p95_us"] = s.p95Us;
  o["p99_us"] = s.p99Us;
  o["p99_9_us"] = s.p999Us;
  o["max_us"] = s.maxUs;
  o["stddev_us"] = s.stddevUs;
  return o;
}

// -------------------------------------------------------------------------
// Throughput test
// -------------------------------------------------------------------------

struct SessionHandle
{
  ua::client::Client client;
  ua::client::SecureChannel channel;
  ua::client::Session session;
  /// The node this session reads; distinct per session when a pool is configured.
  ua::NodeId node{};
};

/// Run one worker's share of the throughput ramp at a given load step.
///
/// Send instants come from a schedule fixed before the step begins, shared by
/// every worker. This is deliberate: pacing from the end of the previous call
/// would let a slow server throttle its own load, because the worker would issue
/// fewer requests instead of falling behind, and the queueing delay would never
/// reach the samples. Response time is therefore measured from the instant the
/// request was due to go out, not from the instant it actually did; service time
/// is kept alongside it so the two can be reported separately.
void throughput_worker(ua::client::Session& session, ua::NodeId node, uint32_t samplesPerWorker,
  int64_t intervalUs, std::chrono::steady_clock::time_point scheduleStart, std::vector<double>& responseOut,
  std::vector<double>& serviceOut, uint32_t& errorsOut)
{
  responseOut.clear();
  responseOut.reserve(samplesPerWorker);
  serviceOut.clear();
  serviceOut.reserve(samplesPerWorker);
  errorsOut = 0;

  const auto interval = std::chrono::microseconds(intervalUs);

  for (uint32_t i = 0; i < samplesPerWorker; ++i)
  {
    const auto due = scheduleStart + interval * i;
    if (std::chrono::steady_clock::now() < due)
    {
      std::this_thread::sleep_until(due);
    }

    auto outcome = issue_read(session, node);
    auto completed = std::chrono::steady_clock::now();

    if (outcome.ok)
    {
      serviceOut.push_back(outcome.serviceUs);
      responseOut.push_back(std::chrono::duration<double, std::micro>(completed - due).count());
    }
    else
    {
      ++errorsOut;
    }
  }
}

void run_throughput_test(PerfServerFixture& fixture, const FuzzerConfig& config, boost::json::object& summary,
  const std::string& outputDir, const ua::Logger& log)
{
  log.info("Starting throughput ramp test");

  auto steps = config.performance.loadSteps;
  auto samplesPerStep = config.baseline.samples;
  const auto& concurrencyLevels = config.performance.throughputConcurrency;

  std::ofstream csv(outputDir + "/throughput_curve.csv");
  csv << "concurrency,step,target_rps,actual_rps,response_p99_us,service_p99_us,error_rate\n";

  boost::json::array allResults;

  for (auto concurrency : concurrencyLevels)
  {
    log.info("Throughput test with {} concurrent session(s)", concurrency);

    // Set up sessions.
    std::vector<SessionHandle> sessions;
    sessions.reserve(concurrency);
    bool setupFailed = false;

    for (uint32_t i = 0; i < concurrency; ++i)
    {
      try
      {
        auto client = fixture.make_client();
        auto channel = client.core().open_channel_sync(fixture.channel_config());
        auto session = channel.create_session_sync({});
        session.activate_sync();
        auto node =
          gGeneratedNodeCount > 0
            ? ua::NodeId(gGeneratedNodeNs, generatedNodeBase + ((i * gNodesPerRead) % gGeneratedNodeCount))
            : (gReadNodePool.empty()
                  ? gReadNodeId
                  : ua::NodeId(gReadNodeId.namespace_index(), gReadNodePool[i % gReadNodePool.size()]));
        sessions.push_back({std::move(client), std::move(channel), std::move(session), std::move(node)});
      }
      catch (const std::exception& e)
      {
        log.error("Failed to create session {}: {}", i, e.what());
        setupFailed = true;
        break;
      }
    }

    if (setupFailed)
    {
      for (auto& sh : sessions)
      {
        try
        {
          sh.session.close_sync();
          sh.channel.close_sync();
        }
        catch (...)
        {}
      }
      continue;
    }

    // Warm up all sessions.
    for (auto& sh : sessions)
    {
      for (int i = 0; i < 50; ++i)
      {
        measure_read_latency(sh.session);
      }
    }

    // Estimate baseline throughput at this concurrency level.
    // Each session sends samplesPerStep requests in parallel.
    std::vector<uint32_t> baseErrors(concurrency, 0);
    auto baseStart = std::chrono::steady_clock::now();
    {
      std::vector<std::thread> threads;
      uint32_t w = 0;
      for (auto& sh : sessions)
      {
        threads.emplace_back(
          [&sh, samplesPerStep, &baseErrors, w]()
          {
            for (uint32_t i = 0; i < samplesPerStep; ++i)
            {
              if (!issue_read(sh.session, sh.node).ok)
                ++baseErrors[w];
            }
          });
        ++w;
      }
      for (auto& t : threads)
      {
        t.join();
      }
    }
    auto baseDur = std::chrono::duration<double>(std::chrono::steady_clock::now() - baseStart).count();

    uint32_t baseErrorTotal = std::accumulate(baseErrors.begin(), baseErrors.end(), 0u);
    auto baseAttempted = static_cast<double>(samplesPerStep) * static_cast<double>(concurrency);
    double baseRps = baseDur > 0.0 ? (baseAttempted - static_cast<double>(baseErrorTotal)) / baseDur : 0.0;

    if (baseErrorTotal > 0)
    {
      log.error("  Baseline lost {} of {} requests; every target rate below is derived from it",
        baseErrorTotal,
        static_cast<int64_t>(baseAttempted));
    }

    log.info("  Baseline throughput: {} req/sec ({} sessions)", static_cast<int>(baseRps), concurrency);

    double saturationRps = 0.0;
    double prevP99 = 0.0;

    boost::json::array throughputCurve;

    for (uint32_t step = 1; step <= steps; ++step)
    {
      // Target rate ramps from 10% to 200% of baseline.
      // A single-step ramp divides by zero here and every derived rate becomes NaN,
      // which then prints as INT_MIN and paces the workers off a garbage interval.
      double fraction = (steps > 1)
                          ? 0.1 + (2.0 - 0.1) * static_cast<double>(step - 1) / static_cast<double>(steps - 1)
                          : 1.0;
      double targetRps = baseRps * fraction;
      double targetRpsPerWorker = targetRps / static_cast<double>(concurrency);
      auto intervalUs = static_cast<int64_t>(1'000'000.0 / targetRpsPerWorker);

      // Each worker collects its own latencies.
      std::vector<std::vector<double>> workerResponse(concurrency);
      std::vector<std::vector<double>> workerService(concurrency);
      std::vector<uint32_t> workerErrors(concurrency, 0);

      // Give every worker the same origin, far enough ahead that thread start-up
      // does not eat into the first interval.
      auto stepStart = std::chrono::steady_clock::now();
      auto scheduleStart = stepStart + std::chrono::milliseconds(50);

      std::vector<std::thread> threads;
      for (uint32_t w = 0; w < concurrency; ++w)
      {
        threads.emplace_back(throughput_worker,
          std::ref(sessions[w].session),
          sessions[w].node,
          samplesPerStep,
          intervalUs,
          scheduleStart,
          std::ref(workerResponse[w]),
          std::ref(workerService[w]),
          std::ref(workerErrors[w]));
      }
      for (auto& t : threads)
      {
        t.join();
      }

      auto stepDur = std::chrono::duration<double>(std::chrono::steady_clock::now() - stepStart).count();

      // Aggregate latencies from all workers.
      std::vector<double> allResponse;
      std::vector<double> allService;
      allResponse.reserve(samplesPerStep * concurrency);
      allService.reserve(samplesPerStep * concurrency);
      uint32_t totalErrors = 0;
      for (uint32_t w = 0; w < concurrency; ++w)
      {
        allResponse.insert(allResponse.end(), workerResponse[w].begin(), workerResponse[w].end());
        allService.insert(allService.end(), workerService[w].begin(), workerService[w].end());
        totalErrors += workerErrors[w];
      }

      // Rate is goodput: requests the server actually answered. Counting refusals
      // as throughput would let a failing server post the best number in the run.
      double totalAttempted = static_cast<double>(samplesPerStep) * static_cast<double>(concurrency);
      double totalSuccess = static_cast<double>(allResponse.size());
      double actualRps = stepDur > 0.0 ? totalSuccess / stepDur : 0.0;
      auto stats = compute_stats(allResponse);
      auto serviceStats = compute_stats(allService);
      double errorRate = totalAttempted > 0.0 ? static_cast<double>(totalErrors) / totalAttempted : 0.0;
      // A step that lost requests describes a server that was failing, not one
      // under load. Mark it so no figure is read off it by accident.
      bool quotable = (totalErrors == 0) && (totalSuccess > 0.0);

      // Detect saturation: p99 jumps more than 2x vs previous step. Only steps
      // that completed cleanly can say anything about where saturation lies.
      if (quotable)
      {
        if (saturationRps == 0.0 && prevP99 > 0.0 && stats.p99Us > prevP99 * 2.0)
        {
          saturationRps = actualRps;
        }
        prevP99 = stats.p99Us;
      }

      log.info("  Step {}/{}: target={} actual={} response p99={}us service p99={}us errors={}%{}",
        step,
        steps,
        static_cast<int>(targetRps),
        static_cast<int>(actualRps),
        static_cast<int>(stats.p99Us),
        static_cast<int>(serviceStats.p99Us),
        static_cast<int>(errorRate * 100),
        quotable ? "" : "  [NOT QUOTABLE]");

      csv << concurrency << "," << step << "," << static_cast<int>(targetRps) << ","
          << static_cast<int>(actualRps) << "," << static_cast<int>(stats.p99Us) << ","
          << static_cast<int>(serviceStats.p99Us) << "," << errorRate << "\n";

      boost::json::object stepObj;
      stepObj["step"] = step;
      stepObj["target_rps"] = targetRps;
      stepObj["actual_rps"] = actualRps;
      // p99_us stays the response-time percentile the trend gate already tracks.
      stepObj["p99_us"] = stats.p99Us;
      stepObj["response_p99_us"] = stats.p99Us;
      stepObj["response_p99_9_us"] = stats.p999Us;
      stepObj["service_p99_us"] = serviceStats.p99Us;
      stepObj["error_rate"] = errorRate;
      stepObj["errors"] = totalErrors;
      stepObj["attempted"] = totalAttempted;
      stepObj["succeeded"] = totalSuccess;
      stepObj["quotable"] = quotable;
      throughputCurve.push_back(std::move(stepObj));
    }

    // Saturation is either observed or it is not. Substituting a multiple of the
    // baseline puts a number in the field that no step actually produced.
    bool saturationObserved = saturationRps > 0.0;

    boost::json::object levelResult;
    levelResult["concurrency"] = concurrency;
    levelResult["baseline_rps"] = baseRps;
    levelResult["baseline_errors"] = baseErrorTotal;
    levelResult["saturation_rps"] = saturationRps;
    levelResult["saturation_observed"] = saturationObserved;
    levelResult["quotable"] = (baseErrorTotal == 0);
    levelResult["curve"] = std::move(throughputCurve);
    allResults.push_back(std::move(levelResult));

    if (saturationObserved)
      log.info("  Concurrency {}: saturation at ~{} req/sec", concurrency, static_cast<int>(saturationRps));
    else
      log.info("  Concurrency {}: no saturation point observed within the ramp", concurrency);

    // Teardown sessions.
    for (auto& sh : sessions)
    {
      try
      {
        sh.session.close_sync();
        sh.channel.close_sync();
      }
      catch (...)
      {}
    }
  }

  summary["throughput"] = std::move(allResults);

  log.info("Throughput test complete");
}

// -------------------------------------------------------------------------
// Latency profile test
// -------------------------------------------------------------------------

void run_latency_profile_test(PerfServerFixture& fixture, const FuzzerConfig& config,
  boost::json::object& summary, const std::string& outputDir, const ua::Logger& log)
{
  log.info("Starting latency profile");

  auto client = fixture.make_client();
  auto channel = client.core().open_channel_sync(fixture.channel_config());
  auto session = channel.create_session_sync({});
  session.activate_sync();

  auto samples = config.baseline.samples;

  std::ofstream csv(outputDir + "/latency_profile.csv");
  csv << "service,sample,latency_us,ok\n";

  boost::json::object servicesObj;

  struct ServiceDef
  {
    std::string name;
    std::function<ReadOutcome()> measure;
  };

  std::vector<ServiceDef> services;
  services.push_back({"Read",
    [&]()
    {
      return issue_read(session);
    }});
  services.push_back({"Browse",
    [&]() -> ReadOutcome
    {
      ua::BrowseRequest req;
      ua::BrowseDescription bd;
      bd.node_id() = ua::NodeId(0, 85);
      bd.browse_direction() = ua::BrowseDirection::Forward;
      bd.result_mask() = 63;
      req.nodes_to_browse().push_back(std::move(bd));
      req.requested_max_references_per_node() = 10;

      auto start = std::chrono::steady_clock::now();
      auto resp = session.view().try_browse_sync(std::move(req));
      auto elapsed = std::chrono::steady_clock::now() - start;
      return ReadOutcome{std::chrono::duration<double, std::micro>(elapsed).count(),
        static_cast<bool>(resp) && resp.value().response_header().service_result().is_good()};
    }});
  services.push_back({"Write",
    [&]() -> ReadOutcome
    {
      ua::WriteRequest req;
      ua::WriteValue wv;
      wv.node_id() = ua::NodeId(0, 2258);
      wv.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
      ua::DataValue dv;
      dv.value() = ua::Variant(int32_t{42});
      wv.value() = std::move(dv);
      req.nodes_to_write().push_back(std::move(wv));

      auto start = std::chrono::steady_clock::now();
      auto resp = session.attributes().try_write_sync(std::move(req));
      auto elapsed = std::chrono::steady_clock::now() - start;
      bool ok = static_cast<bool>(resp) && resp.value().response_header().service_result().is_good();
      ua::StatusCode status{};
      if (!ok && static_cast<bool>(resp))
      {
        status = resp.value().response_header().service_result();
      }
      if (ok)
      {
        const auto& results = resp.value().results();
        ok = !results.empty();
        if (results.empty())
        {
          status = ua::StatusCode{ua::Status::BadUnexpectedError};
        }
        for (const auto& st : results)
        {
          if (st.is_not_good())
          {
            ok = false;
            status = st;
            break;
          }
        }
      }
      return ReadOutcome{std::chrono::duration<double, std::micro>(elapsed).count(), ok, status};
    }});

  for (auto& svc : services)
  {
    log.info("Profiling {}...", svc.name);
    uint32_t svcErrors = 0;

    std::vector<double> latencies;
    latencies.reserve(samples);

    for (uint32_t i = 0; i < samples; ++i)
    {
      auto outcome = svc.measure();
      if (outcome.ok)
      {
        latencies.push_back(outcome.serviceUs);
      }
      else
      {
        if (svcErrors == 0)
        {
          log.error("  {}: first refusal status = {} (0x{:08X})",
            svc.name,
            ua::to_string(outcome.status.as_status()),
            static_cast<uint32_t>(outcome.status.value()));
        }
        ++svcErrors;
      }
      csv << svc.name << "," << i << "," << outcome.serviceUs << "," << (outcome.ok ? 1 : 0) << "\n";
    }

    auto stats = compute_stats(latencies);
    auto statsObj = stats_to_json(stats);
    statsObj["errors"] = svcErrors;
    statsObj["succeeded"] = latencies.size();
    statsObj["quotable"] = (svcErrors == 0) && !latencies.empty();
    if (svcErrors > 0)
    {
      log.error("  {}: {} of {} calls were refused; this profile is not a measurement of {}",
        svc.name,
        svcErrors,
        samples,
        svc.name);
    }
    servicesObj[svc.name] = std::move(statsObj);

    log.info("  {}: p50={}us p99={}us p99.9={}us",
      svc.name,
      static_cast<int>(stats.p50Us),
      static_cast<int>(stats.p99Us),
      static_cast<int>(stats.p999Us));
  }

  summary["latency_profile"] = std::move(servicesObj);

  session.close_sync();
  channel.close_sync();

  log.info("Latency profile complete");
}

// -------------------------------------------------------------------------
// Soak test
// -------------------------------------------------------------------------

void run_soak_test(PerfServerFixture& fixture, const FuzzerConfig& config, boost::json::object& summary,
  const std::string& outputDir, const ua::Logger& log)
{
  auto durationSec = config.performance.soakDurationS;
  log.info("Starting soak test ({}s)", durationSec);

  auto client = fixture.make_client();
  auto channel = client.core().open_channel_sync(fixture.channel_config());
  auto session = channel.create_session_sync({});
  session.activate_sync();

  std::ofstream csv(outputDir + "/latency_over_time.csv");
  csv << "elapsed_s,p50_us,p95_us,p99_us,requests\n";

  // Resource time-series, sampled on the same tick as latency_over_time.csv so
  // the soak/leak jobs can spot Class-2 (reachable RSS growth) and Class-3 (FD)
  // leaks that LSan misses.
  std::ofstream rssCsv(outputDir + "/rss_over_time.csv");
  rssCsv << "elapsed_s,rss_kib\n";
  std::ofstream fdCsv(outputDir + "/fd_over_time.csv");
  fdCsv << "elapsed_s,open_fds\n";

  // Post-warmup RSS samples (elapsed seconds, rss in kiB) for slope analysis.
  std::vector<double> rssSampleElapsed;
  std::vector<double> rssSampleKib;

  auto soakStart = std::chrono::steady_clock::now();
  auto deadline = soakStart + std::chrono::seconds(durationSec);

  uint64_t totalRequests = 0;
  std::vector<double> windowLatencies;
  windowLatencies.reserve(1000);

  auto lastReport = soakStart;
  double startP50 = 0.0;
  double endP50 = 0.0;
  uint64_t soakErrors = 0;

  while (std::chrono::steady_clock::now() < deadline)
  {
    auto outcome = issue_read(session);
    if (outcome.ok)
    {
      windowLatencies.push_back(outcome.serviceUs);
    }
    else
    {
      ++soakErrors;
    }
    ++totalRequests;

    auto now = std::chrono::steady_clock::now();
    if (now - lastReport >= std::chrono::seconds(10) && !windowLatencies.empty())
    {
      auto elapsed = std::chrono::duration<double>(now - soakStart).count();
      auto stats = compute_stats(windowLatencies);

      csv << static_cast<int>(elapsed) << "," << static_cast<int>(stats.p50Us) << ","
          << static_cast<int>(stats.p95Us) << "," << static_cast<int>(stats.p99Us) << ","
          << windowLatencies.size() << "\n";

      // Sample resource usage on the same tick. Skip a sample gracefully if the
      // /proc read fails.
      if (auto rssKib = read_self_rss_kib())
      {
        rssCsv << static_cast<int>(elapsed) << "," << *rssKib << "\n";
        rssSampleElapsed.push_back(elapsed);
        rssSampleKib.push_back(static_cast<double>(*rssKib));
      }
      if (auto openFds = count_open_fds())
      {
        fdCsv << static_cast<int>(elapsed) << "," << *openFds << "\n";
      }

      if (startP50 == 0.0)
        startP50 = stats.p50Us;
      endP50 = stats.p50Us;

      log.info("Soak: {}s p50={}us total={}",
        static_cast<int>(elapsed),
        static_cast<int>(stats.p50Us),
        totalRequests);

      windowLatencies.clear();
      lastReport = now;
    }
  }

  auto totalDur = std::chrono::duration<double>(std::chrono::steady_clock::now() - soakStart).count();
  double driftUsPerHour = 0.0;
  if (totalDur > 0.0 && startP50 > 0.0)
  {
    driftUsPerHour = (endP50 - startP50) / (totalDur / 3600.0);
  }

  // Compute the RSS-growth slope over post-warmup samples, discarding the first
  // sample as warmup. Fewer than two post-warmup samples yields a zero slope.
  double rssSlopeBytesPerS = 0.0;
  double rssFirstKib = 0.0;
  double rssLastKib = 0.0;
  if (rssSampleKib.size() >= 2)
  {
    std::vector<double> warmElapsed(rssSampleElapsed.begin() + 1, rssSampleElapsed.end());
    std::vector<double> warmKib(rssSampleKib.begin() + 1, rssSampleKib.end());

    if (!warmKib.empty())
    {
      rssFirstKib = warmKib.front();
      rssLastKib = warmKib.back();
    }

    std::vector<double> warmBytes;
    warmBytes.reserve(warmKib.size());
    for (auto kib : warmKib)
      warmBytes.push_back(kib * 1024.0);

    rssSlopeBytesPerS = least_squares_slope(warmElapsed, warmBytes);
  }

  if (soakErrors > 0)
  {
    log.error("Soak lost {} of {} requests; the latency trend below is not quotable",
      soakErrors,
      static_cast<int64_t>(totalRequests));
  }

  summary["soak"] = boost::json::object{{"duration_s", static_cast<int>(totalDur)},
    {"total_requests", static_cast<int64_t>(totalRequests)},
    {"errors", static_cast<int64_t>(soakErrors)},
    {"quotable", soakErrors == 0},
    {"avg_rps", static_cast<double>(totalRequests) / totalDur},
    {"start_p50_us", startP50},
    {"end_p50_us", endP50},
    {"latency_drift_us_per_hour", driftUsPerHour},
    {"rss_slope_bytes_per_s", rssSlopeBytesPerS},
    {"rss_first_kib", rssFirstKib},
    {"rss_last_kib", rssLastKib}};

  session.close_sync();
  channel.close_sync();

  log.info(
    "Soak test complete, {} requests, drift={}us/hour", totalRequests, static_cast<int>(driftUsPerHour));
}

// -------------------------------------------------------------------------
// Concurrency test
// -------------------------------------------------------------------------

void run_concurrency_test(
  PerfServerFixture& fixture, const FuzzerConfig& config, boost::json::object& summary, const ua::Logger& log)
{
  log.info("Starting concurrency test");

  auto samples = std::min(config.baseline.samples, 50u);

  boost::json::array results;

  for (auto sessionCount : config.performance.concurrencySteps)
  {
    log.info("Testing with {} concurrent sessions", sessionCount);

    // Create N sessions.
    std::vector<SessionHandle> sessions;
    sessions.reserve(sessionCount);

    bool setupFailed = false;

    for (uint32_t i = 0; i < sessionCount; ++i)
    {
      try
      {
        auto client = fixture.make_client();
        auto channel = client.core().open_channel_sync(fixture.channel_config());
        auto session = channel.create_session_sync({});
        session.activate_sync();
        sessions.push_back({std::move(client), std::move(channel), std::move(session), gReadNodeId});
      }
      catch (const std::exception& e)
      {
        log.error("Failed to create session {}: {}", i, e.what());
        setupFailed = true;
        break;
      }
    }

    if (setupFailed)
    {
      // Clean up what we have.
      for (auto& sh : sessions)
      {
        try
        {
          sh.session.close_sync();
          sh.channel.close_sync();
        }
        catch (...)
        {}
      }
      continue;
    }

    // Measure latency across all sessions in round-robin.
    std::vector<double> latencies;
    latencies.reserve(samples * sessionCount);
    uint64_t concErrors = 0;

    for (uint32_t s = 0; s < samples; ++s)
    {
      for (auto& sh : sessions)
      {
        try
        {
          // A sentinel pushed here would sort to the front and move every
          // percentile; failures are counted, never measured.
          auto outcome = issue_read(sh.session);
          if (outcome.ok)
            latencies.push_back(outcome.serviceUs);
          else
            ++concErrors;
        }
        catch (...)
        {
          ++concErrors;
        }
      }
    }

    // Remove failed measurements.

    auto stats = compute_stats(latencies);

    log.info("  {} sessions: p50={}us p99={}us",
      sessionCount,
      static_cast<int>(stats.p50Us),
      static_cast<int>(stats.p99Us));

    boost::json::object stepObj;
    stepObj["session_count"] = sessionCount;
    stepObj["latency"] = stats_to_json(stats);
    stepObj["errors"] = concErrors;
    stepObj["succeeded"] = latencies.size();
    stepObj["quotable"] = (concErrors == 0) && !latencies.empty();
    if (concErrors > 0)
    {
      log.error("  {} sessions: {} calls failed; this level is not quotable", sessionCount, concErrors);
    }
    results.push_back(std::move(stepObj));

    // Teardown.
    for (auto& sh : sessions)
    {
      try
      {
        sh.session.close_sync();
        sh.channel.close_sync();
      }
      catch (...)
      {}
    }
  }

  summary["concurrency"] = std::move(results);

  log.info("Concurrency test complete");
}

// -------------------------------------------------------------------------
// Subscription stress test
// -------------------------------------------------------------------------

namespace
{

/// Tracked state for a single subscription within a session.
struct SubscriptionState
{
  uint32_t subscriptionId{0};
  std::vector<uint32_t> monitoredItemIds;
  /// What the server actually granted. A server may revise both intervals, and a
  /// sample-rate figure computed from what was *requested* would then be wrong.
  double revisedPublishingMs{0.0};
  double revisedSamplingMs{0.0};
  uint32_t itemsRejected{0};
};

/// Per-session metrics collected by each publish thread.
struct SessionPublishMetrics
{
  std::vector<double> publishLatencies;
  uint64_t totalPublishes{0};
  /// NotificationData structures received - normally one DataChangeNotification
  /// per Publish response, so this tracks messages, not data changes.
  uint64_t totalNotificationMessages{0};
  /// MonitoredItemNotifications inside those structures: the actual data changes
  /// delivered. This is the figure a subscription throughput claim rests on.
  uint64_t totalDataChanges{0};
  /// Failure statuses seen by the publish worker, counted by name. Without this a run that
  /// fails every Publish is indistinguishable from one that succeeds slowly: both report a
  /// count. D18 was found because the count alone could not say what had gone wrong.
  std::map<std::string, uint64_t> publishErrorStatuses;
  /// Notification delivery latency in microseconds: the interval between the server stamping a
  /// value and the client holding it, corrected for the clock offset between the hosts. One
  /// sample per Publish response.
  std::vector<double> notificationLatencies;
  uint64_t latencyFromServerStamp{0};
  uint64_t latencyFromSourceStamp{0};
  uint64_t latencyNoStamp{0};
  /// Latency of the NEWEST notification in each response; notificationLatencies holds the oldest.
  std::vector<double> newestLatencies;
  uint64_t publishErrors{0};
};

/// Per-session state used during the subscription load test.
struct SubscriptionSessionState
{
  std::optional<SessionHandle> handle;
  std::vector<SubscriptionState> subscriptions;
  std::mutex mutex;  // protects subscriptions during churn
};

constexpr std::array<double, 4> publishingIntervals = {100.0, 200.0, 500.0, 1000.0};
constexpr std::array<uint8_t, 4> priorities = {0, 64, 128, 255};

/// Create a single subscription with monitored items on the given session.
/// Returns the subscription state, and appends latencies to the output vectors.
SubscriptionState create_subscription_with_items(ua::client::Session& session, uint32_t itemCount,
  double publishingInterval, uint8_t priority, double& subCreateLatencyOut, double& monCreateLatencyOut,
  const ua::Logger& log, double samplingInterval = 0.0, bool useGeneratedNodes = false,
  uint32_t nodeOffset = 0, uint32_t maxNotificationsPerPublish = 0)
{
  SubscriptionState state;

  ua::CreateSubscriptionRequest subReq;
  subReq.requested_publishing_interval() = publishingInterval;
  subReq.requested_lifetime_count() = 600;
  subReq.requested_max_keep_alive_count() = 5;
  subReq.max_notifications_per_publish() = maxNotificationsPerPublish;
  subReq.publishing_enabled() = true;
  subReq.priority() = priority;

  auto subStart = std::chrono::steady_clock::now();
  auto subResp = session.subscriptions().try_create_subscription_sync(std::move(subReq));
  subCreateLatencyOut =
    std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - subStart).count();

  if (!subResp.is_good())
  {
    log.error("CreateSubscription failed: {}", subResp.status_code().as_uint32());
    return state;
  }

  state.subscriptionId = subResp.value().subscription_id();
  state.revisedPublishingMs = subResp.value().revised_publishing_interval();

  // Create monitored items.
  ua::CreateMonitoredItemsRequest monReq;
  monReq.subscription_id() = state.subscriptionId;
  monReq.timestamps_to_return() = ua::TimestampsToReturn::Both;

  for (uint32_t i = 0; i < itemCount; ++i)
  {
    ua::MonitoredItemCreateRequest item;
    ua::ReadValueId rv;
    if (useGeneratedNodes && gGeneratedNodeCount > 0)
    {
      // One node per item, so the items do not all contend on a single node.
      rv.node_id() =
        ua::NodeId(gGeneratedNodeNs, generatedNodeBase + ((nodeOffset + i) % gGeneratedNodeCount));
    }
    else
    {
      rv.node_id() = ua::NodeId(0, 2258);  // Server_ServerStatus_CurrentTime
    }
    rv.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
    item.item_to_monitor() = std::move(rv);
    item.monitoring_mode() = ua::MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = i;
    item.requested_parameters().sampling_interval() =
      samplingInterval > 0.0 ? samplingInterval : publishingInterval;
    item.requested_parameters().queue_size() = 10;
    item.requested_parameters().discard_oldest() = true;
    monReq.items_to_create().push_back(std::move(item));
  }

  auto monStart = std::chrono::steady_clock::now();
  auto monResp = session.monitored_items().try_create_monitored_items_sync(std::move(monReq));
  monCreateLatencyOut =
    std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - monStart).count();

  if (!monResp.is_good())
  {
    log.error(
      "CreateMonitoredItems failed for sub {}: {}", state.subscriptionId, monResp.status_code().as_uint32());
    return state;
  }

  for (auto& result : monResp.value().results())
  {
    if (result.status_code().is_not_good())
    {
      ++state.itemsRejected;
      continue;
    }
    state.monitoredItemIds.push_back(result.monitored_item_id());
    // Every item requested the same interval, so the first granted one characterises
    // all of them; a divergence would show as a differing value here.
    if (state.revisedSamplingMs == 0.0)
    {
      state.revisedSamplingMs = result.revised_sampling_interval();
    }
  }

  return state;
}

/// Delete a subscription and its monitored items from a session.
void delete_subscription(ua::client::Session& session, const SubscriptionState& sub)
{
  ua::DeleteSubscriptionsRequest delReq;
  delReq.subscription_ids().push_back(sub.subscriptionId);
  auto delResp = session.subscriptions().try_delete_subscriptions_sync(std::move(delReq));
  (void)delResp;
}

/// Publish loop for one session. Runs until the stop flag is set.
/// Estimates the clock offset between this host and the server, NTP-style.
///
/// Latency is measured as (client receive time - server sample timestamp), and those two clocks
/// belong to different machines. Any offset between them lands directly in the answer, so it is
/// measured rather than assumed to be zero - even with both hosts running NTP.
///
/// Server_ServerStatus_CurrentTime carries the server's own clock as its *value*, so a timed Read
/// of it gives everything needed: offset = server_time - midpoint(send, receive), on the usual
/// assumption that the path is symmetric. The median of several probes is returned, and the spread
/// is reported so the reader can judge how much of a sub-millisecond latency figure is offset
/// uncertainty.
std::chrono::nanoseconds probe_clock_offset(
  ua::client::Session& session, const ua::Logger& log, int probes = 21)
{
  std::vector<double> offsetsNs;
  offsetsNs.reserve(static_cast<size_t>(probes));

  for (int i = 0; i < probes; ++i)
  {
    ua::ReadRequest req;
    ua::ReadValueId rv;
    rv.node_id() = ua::NodeId{0, 2258};
    rv.attribute_id() = static_cast<uint32_t>(ua::AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));

    const auto t0 = std::chrono::system_clock::now();
    auto resp = session.attributes().try_read_sync(std::move(req));
    const auto t1 = std::chrono::system_clock::now();

    if (!resp.is_good() || resp.value().results().empty())
      continue;
    const auto& dv = resp.value().results()[0];
    const ua::DateTime* dt = dv.value().try_as<ua::DateTime>();
    if (dt == nullptr || dt->is_null())
      continue;

    // Both sides are std::chrono::sys_time, which counts from the Unix epoch regardless of the
    // OPC UA wire epoch, so they are directly comparable. Subtracting DateTime::min() here was a
    // bug: it shifted only the client side and produced an offset of about 215 years.
    const auto serverNs =
      std::chrono::duration_cast<std::chrono::nanoseconds>(dt->value().time_since_epoch());
    const auto midpoint = t0 + (t1 - t0) / 2;
    const auto clientNs = std::chrono::duration_cast<std::chrono::nanoseconds>(midpoint.time_since_epoch());
    offsetsNs.push_back(static_cast<double>((serverNs - clientNs).count()));
  }

  if (offsetsNs.empty())
  {
    log.info("  Clock offset: could not be measured; latency will be reported uncorrected");
    return std::chrono::nanoseconds{0};
  }

  std::sort(offsetsNs.begin(), offsetsNs.end());
  const double median = offsetsNs[offsetsNs.size() / 2];
  log.info("  Clock offset vs server: median {:.0f} us over {} probes, spread {:.0f} us",
    median / 1000.0,
    offsetsNs.size(),
    (offsetsNs.back() - offsetsNs.front()) / 1000.0);
  return std::chrono::nanoseconds{static_cast<int64_t>(median)};
}

void publish_worker(SubscriptionSessionState& sessionState, std::atomic<bool>& stopFlag,
  SessionPublishMetrics& metricsOut, bool measureLatency, std::chrono::nanoseconds clockOffset)
{
  // Track pending acknowledgements per subscription.
  // Key: subscription_id, Value: sequence numbers to acknowledge.
  std::unordered_map<uint32_t, std::vector<uint32_t>> pendingAcks;
  uint32_t consecutiveErrors = 0;

  while (!stopFlag.load(std::memory_order_relaxed))
  {
    ua::PublishRequest pubReq;

    // Build acknowledgements from previous responses.
    for (auto& [subId, seqNums] : pendingAcks)
    {
      for (auto seqNum : seqNums)
      {
        ua::SubscriptionAcknowledgement ack;
        ack.subscription_id() = subId;
        ack.sequence_number() = seqNum;
        pubReq.subscription_acknowledgements().push_back(std::move(ack));
      }
    }
    pendingAcks.clear();

    auto pubStart = std::chrono::steady_clock::now();
    auto pubResp = sessionState.handle->session.subscriptions().try_publish_sync(std::move(pubReq));
    auto pubElapsed =
      std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - pubStart).count();

    ++metricsOut.totalPublishes;

    if (pubResp.is_good())
    {
      metricsOut.publishLatencies.push_back(pubElapsed);

      auto& resp = pubResp.value();
      auto subId = resp.subscription_id();
      auto seqNum = resp.notification_message().sequence_number();

      // Queue this sequence number for acknowledgement in the next publish.
      pendingAcks[subId].push_back(seqNum);

      // notification_data() holds NotificationData structures, normally one
      // DataChangeNotification per response. Counting them counts messages; the
      // data changes live in its monitored_items() array and must be reached
      // through the polymorphic base.
      auto& notifData = resp.notification_message().notification_data();
      metricsOut.totalNotificationMessages += notifData.size();
      bool latencyTaken = false;
      for (const auto& entry : notifData)
      {
        if (const auto* change = dynamic_cast<const ua::DataChangeNotification*>(entry.get()))
        {
          metricsOut.totalDataChanges += change->monitored_items().size();

          // One latency sample per response. Sampling every data change would make the
          // measurement cost scale with the notification rate, which at 400,000/s would
          // perturb what it is measuring.
          // A Publish response carries a queue of notifications: the first entry is the oldest
          // and the last the newest. Sampling only one conflates "how long did a change wait"
          // with "which end of the queue did I happen to look at", so both ends are recorded and
          // the pair brackets the queueing delay within a response.
          if (measureLatency && !latencyTaken && change->monitored_items().size() > 0)
          {
            const auto& newest = change->monitored_items()[change->monitored_items().size() - 1];
            const ua::DateTime* nstamp = nullptr;
            if (newest.value().server_timestamp().has_value() &&
                !newest.value().server_timestamp()->is_null())
              nstamp = &*newest.value().server_timestamp();
            else if (newest.value().source_timestamp().has_value() &&
                     !newest.value().source_timestamp()->is_null())
              nstamp = &*newest.value().source_timestamp();
            if (nstamp != nullptr)
            {
              const auto sampledN =
                std::chrono::duration_cast<std::chrono::nanoseconds>(nstamp->value().time_since_epoch());
              const auto receivedN = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch());
              metricsOut.newestLatencies.push_back(
                std::chrono::duration<double, std::micro>(receivedN - sampledN - clockOffset).count());
            }

            const auto& first = change->monitored_items()[0];
            // Server timestamp is what the latency question is about - when the server produced
            // the value. Source is accepted as a fallback so a server that omits one still yields
            // a figure, and the counters below say which was used.
            const ua::DateTime* stamp = nullptr;
            if (first.value().server_timestamp().has_value() && !first.value().server_timestamp()->is_null())
            {
              stamp = &*first.value().server_timestamp();
              ++metricsOut.latencyFromServerStamp;
            }
            else if (first.value().source_timestamp().has_value() &&
                     !first.value().source_timestamp()->is_null())
            {
              stamp = &*first.value().source_timestamp();
              ++metricsOut.latencyFromSourceStamp;
            }
            else
            {
              ++metricsOut.latencyNoStamp;
            }

            if (stamp != nullptr)
            {
              const auto sampled =
                std::chrono::duration_cast<std::chrono::nanoseconds>(stamp->value().time_since_epoch());
              const auto received = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch());
              const auto delta = received - sampled - clockOffset;
              metricsOut.notificationLatencies.push_back(
                std::chrono::duration<double, std::micro>(delta).count());
              latencyTaken = true;
            }
          }
        }
      }
    }
    else
    {
      ++metricsOut.publishErrors;
      ++metricsOut.publishErrorStatuses[ua::to_string(pubResp.status_code().as_status())];

      // Back off before retrying. Without this the loop reissues immediately, and a session
      // that has stopped answering turns into a spin: a measured 85,000 failed Publishes per
      // second, which burns generator CPU, inflates the publish count by three orders of
      // magnitude, and can starve the sessions that are still healthy. Exponential to 100 ms so
      // an isolated failure costs a millisecond and a persistent one costs nothing at all.
      ++consecutiveErrors;
      const auto shift = std::min<uint32_t>(consecutiveErrors, 7);
      std::this_thread::sleep_for(std::chrono::milliseconds{std::min<uint64_t>(100, 1ull << shift)});
      continue;
    }
    consecutiveErrors = 0;
  }
}

}  // namespace

void run_subscription_stress_test(
  PerfServerFixture& fixture, const FuzzerConfig& config, boost::json::object& summary, const ua::Logger& log)
{
  log.info("Starting subscription stress test");

  auto sessionCount = config.performance.subscriptionSessionCount;
  auto subsPerSession = config.performance.subscriptionsPerSession;
  auto itemsPerSub = config.performance.monitoredItemsPerSubscription;
  auto soakDuration = config.performance.subscriptionSoakDurationS;
  auto churnEnabled = config.performance.subscriptionChurnEnabled;

  auto totalItems = sessionCount * subsPerSession * itemsPerSub;
  uint32_t totalItemsCreated = 0;
  uint32_t totalItemsRejected = 0;
  double grantedSamplingMs = 0.0;
  double grantedPublishingMs = 0.0;
  double expectedSamplesPerSec = 0.0;
  std::set<double> grantedIntervals;
  const double samplingIntervalMs = config.performance.subSamplingIntervalMs;
  const bool useGeneratedNodes = config.performance.subUseGeneratedNodes;

  log.info("Subscription config: publishing={}ms sampling={} nodes={}",
    config.performance.subPublishingIntervalMs > 0.0
      ? std::to_string(config.performance.subPublishingIntervalMs)
      : std::string("rotating defaults"),
    samplingIntervalMs > 0.0 ? std::to_string(samplingIntervalMs) : std::string("= publishing interval"),
    useGeneratedNodes ? "generated scalars (static)" : "ns=0;i=2258 CurrentTime (dynamic)");
  log.info("Config: {} sessions x {} subs x {} items = {} total monitored items",
    sessionCount,
    subsPerSession,
    itemsPerSub,
    totalItems);

  // -----------------------------------------------------------------------
  // Phase 1: Setup - create sessions, subscriptions, and monitored items
  // -----------------------------------------------------------------------
  log.info("Phase 1: Setup");
  auto setupStart = std::chrono::steady_clock::now();

  std::vector<std::unique_ptr<SubscriptionSessionState>> sessions;
  sessions.reserve(sessionCount);

  std::vector<double> subCreateLatencies;
  std::vector<double> monCreateLatencies;
  subCreateLatencies.reserve(sessionCount * subsPerSession);
  monCreateLatencies.reserve(sessionCount * subsPerSession);

  bool setupFailed = false;

  for (uint32_t si = 0; si < sessionCount; ++si)
  {
    log.info("  Creating session {}/{}", si + 1, sessionCount);

    try
    {
      auto client = fixture.make_client();
      auto channel = client.core().open_channel_sync(fixture.channel_config());
      auto session = channel.create_session_sync({});
      session.activate_sync();

      auto state = std::make_unique<SubscriptionSessionState>();
      state->handle = SessionHandle{std::move(client), std::move(channel), std::move(session)};

      for (uint32_t subi = 0; subi < subsPerSession; ++subi)
      {
        const auto& intervalSet = config.performance.subIntervalSet;
        const double thisSampling = intervalSet.empty()
                                      ? config.performance.subSamplingIntervalMs
                                      : intervalSet[(si * subsPerSession + subi) % intervalSet.size()];

        double publishingInterval =
          config.performance.subPublishingIntervalMs > 0.0
            ? config.performance.subPublishingIntervalMs
            : publishingIntervals[(si * subsPerSession + subi) % publishingIntervals.size()];
        uint8_t priority = priorities[(si * subsPerSession + subi) % priorities.size()];

        double subLatency = 0.0;
        double monLatency = 0.0;
        // Distinct node window per subscription, so items across the whole run spread
        // over the generated pool rather than stacking on the same few nodes.
        const uint32_t nodeOffset = (si * subsPerSession + subi) * itemsPerSub;
        auto sub = create_subscription_with_items(state->handle->session,
          itemsPerSub,
          publishingInterval,
          priority,
          subLatency,
          monLatency,
          log,
          thisSampling,
          config.performance.subUseGeneratedNodes,
          nodeOffset,
          config.performance.subMaxNotificationsPerPublish);

        if (sub.subscriptionId == 0)
        {
          log.error("  Failed to create subscription {}/{} on session {}", subi + 1, subsPerSession, si + 1);
          continue;
        }

        if (si == 0 && subi == 0)
        {
          log.info("  Server granted: publishing={}ms sampling={}ms items_created={} items_rejected={}",
            sub.revisedPublishingMs,
            sub.revisedSamplingMs,
            sub.monitoredItemIds.size(),
            sub.itemsRejected);
        }
        totalItemsCreated += static_cast<uint32_t>(sub.monitoredItemIds.size());
        totalItemsRejected += sub.itemsRejected;
        grantedSamplingMs = sub.revisedSamplingMs;
        grantedPublishingMs = sub.revisedPublishingMs;
        // Expected sample rate is the sum over subscriptions, not items x one
        // interval: with an interval set each subscription samples at its own rate.
        if (sub.revisedSamplingMs > 0.0)
        {
          expectedSamplesPerSec +=
            static_cast<double>(sub.monitoredItemIds.size()) * (1000.0 / sub.revisedSamplingMs);
          grantedIntervals.insert(sub.revisedSamplingMs);
        }

        subCreateLatencies.push_back(subLatency);
        monCreateLatencies.push_back(monLatency);
        state->subscriptions.push_back(std::move(sub));

        if ((subi + 1) % 5 == 0 || subi + 1 == subsPerSession)
        {
          log.info("    Session {}: created {}/{} subscriptions", si + 1, subi + 1, subsPerSession);
        }
      }

      sessions.push_back(std::move(state));
    }
    catch (const std::exception& e)
    {
      log.error("  Failed to create session {}: {}", si + 1, e.what());
      setupFailed = true;
      break;
    }
  }

  auto setupElapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - setupStart).count();
  auto subCreateStats = compute_stats(subCreateLatencies);
  auto monCreateStats = compute_stats(monCreateLatencies);

  log.info("Setup complete in {:.1f}s: {} sessions, {} total subscriptions",
    setupElapsed,
    sessions.size(),
    subCreateLatencies.size());
  log.info("  Sub create latency: p50={}us p99={}us",
    static_cast<int>(subCreateStats.p50Us),
    static_cast<int>(subCreateStats.p99Us));
  log.info("  MonItems create latency: p50={}us p99={}us",
    static_cast<int>(monCreateStats.p50Us),
    static_cast<int>(monCreateStats.p99Us));

  if (setupFailed || sessions.empty())
  {
    log.error("Setup failed, cleaning up");
    for (auto& state : sessions)
    {
      for (auto& sub : state->subscriptions)
      {
        try
        {
          delete_subscription(state->handle->session, sub);
        }
        catch (...)
        {}
      }
      try
      {
        state->handle->session.close_sync();
        state->handle->channel.close_sync();
      }
      catch (...)
      {}
    }
    return;
  }

  // -----------------------------------------------------------------------
  // Phase 2: Concurrent Publish Soak
  // -----------------------------------------------------------------------
  log.info("Phase 2: Concurrent publish soak for {}s", soakDuration);

  std::atomic<bool> publishStopFlag{false};
  std::vector<SessionPublishMetrics> sessionMetrics(sessions.size());
  std::vector<std::thread> publishThreads;

  // Measured before the soak so the probe's own Reads do not compete with the notification load.
  const bool measureLatency = config.performance.subMeasureLatency;
  std::chrono::nanoseconds clockOffset{0};
  if (measureLatency && !sessions.empty())
  {
    clockOffset = probe_clock_offset(sessions.front()->handle->session, log);
  }

  for (size_t si = 0; si < sessions.size(); ++si)
  {
    sessionMetrics[si].publishLatencies.reserve(soakDuration * 20);  // rough estimate
    publishThreads.emplace_back(publish_worker,
      std::ref(*sessions[si]),
      std::ref(publishStopFlag),
      std::ref(sessionMetrics[si]),
      measureLatency,
      clockOffset);
  }

  // -----------------------------------------------------------------------
  // Phase 3: Subscription Churn (concurrent with publish soak)
  // -----------------------------------------------------------------------
  std::vector<double> churnLatencies;
  uint64_t churnOps = 0;
  std::thread churnThread;

  if (churnEnabled && sessions.size() > 0)
  {
    auto churnDuration = std::max(10u, soakDuration / 3);
    log.info("Phase 3: Subscription churn for {}s (concurrent with publish)", churnDuration);

    churnThread = std::thread(
      [&sessions,
        &churnLatencies,
        &churnOps,
        churnDuration,
        itemsPerSub,
        &log,
        samplingIntervalMs,
        useGeneratedNodes]()
      {
        std::mt19937 rng(std::random_device{}());
        auto churnDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(churnDuration);

        while (std::chrono::steady_clock::now() < churnDeadline)
        {
          // Pick a random session.
          std::uniform_int_distribution<size_t> sessionDist(0, sessions.size() - 1);
          auto sessionIdx = sessionDist(rng);
          auto& sessionState = *sessions[sessionIdx];

          std::lock_guard<std::mutex> lock(sessionState.mutex);

          if (sessionState.subscriptions.empty())
            continue;

          // Delete a random subscription.
          std::uniform_int_distribution<size_t> subDist(0, sessionState.subscriptions.size() - 1);
          auto subIdx = subDist(rng);
          auto oldSub = sessionState.subscriptions[subIdx];

          auto churnStart = std::chrono::steady_clock::now();

          try
          {
            delete_subscription(sessionState.handle->session, oldSub);
          }
          catch (const std::exception& e)
          {
            log.error("Churn delete failed: {}", e.what());
            continue;
          }

          // Create a replacement subscription.
          double publishingInterval = publishingIntervals[churnOps % publishingIntervals.size()];
          uint8_t priority = priorities[churnOps % priorities.size()];
          double subLatency = 0.0;
          double monLatency = 0.0;

          try
          {
            auto newSub = create_subscription_with_items(sessionState.handle->session,
              itemsPerSub,
              publishingInterval,
              priority,
              subLatency,
              monLatency,
              log,
              samplingIntervalMs,
              useGeneratedNodes,
              0);

            if (newSub.subscriptionId != 0)
            {
              sessionState.subscriptions[subIdx] = std::move(newSub);
            }
            else
            {
              // Remove the slot if creation failed.
              sessionState.subscriptions.erase(
                sessionState.subscriptions.begin() + static_cast<ptrdiff_t>(subIdx));
            }
          }
          catch (const std::exception& e)
          {
            log.error("Churn create failed: {}", e.what());
            sessionState.subscriptions.erase(
              sessionState.subscriptions.begin() + static_cast<ptrdiff_t>(subIdx));
            continue;
          }

          auto churnElapsed =
            std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - churnStart).count();
          churnLatencies.push_back(churnElapsed);
          ++churnOps;

          // Small pause between churn operations to avoid overwhelming the server.
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
      });
  }

  // Periodic stats logging during the soak.
  {
    auto soakStart = std::chrono::steady_clock::now();
    auto soakDeadline = soakStart + std::chrono::seconds(soakDuration);
    auto lastReport = soakStart;

    while (std::chrono::steady_clock::now() < soakDeadline)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));

      auto now = std::chrono::steady_clock::now();
      if (now - lastReport >= std::chrono::seconds(10))
      {
        auto elapsed = std::chrono::duration<double>(now - soakStart).count();

        uint64_t totalPublishes = 0;
        uint64_t totalNotifications = 0;
        uint64_t totalDataChanges = 0;
        std::vector<double> allLatencies;

        for (size_t si = 0; si < sessions.size(); ++si)
        {
          totalPublishes += sessionMetrics[si].totalPublishes;
          totalNotifications += sessionMetrics[si].totalNotificationMessages;
          totalDataChanges += sessionMetrics[si].totalDataChanges;
          // Racy cross-thread read of the per-session counters, but acceptable: these are
          // only summed for periodic logging, never for correctness.
        }

        double notifPerSec = static_cast<double>(totalDataChanges) / elapsed;
        log.info("  Soak {:.0f}s: publishes={} notif_msgs={} data_changes={} changes/s={:.0f} churn_ops={}",
          elapsed,
          totalPublishes,
          totalNotifications,
          totalDataChanges,
          notifPerSec,
          churnOps);

        lastReport = now;
      }
    }
  }

  // Stop publish threads.
  publishStopFlag.store(true, std::memory_order_relaxed);
  for (auto& thread : publishThreads)
  {
    thread.join();
  }

  // Wait for churn thread.
  if (churnThread.joinable())
  {
    churnThread.join();
  }

  log.info("Publish soak and churn complete");

  // -----------------------------------------------------------------------
  // Phase 4: Teardown and Metrics
  // -----------------------------------------------------------------------
  log.info("Phase 4: Teardown and metrics");

  // Aggregate publish metrics across all sessions.
  std::vector<double> allPublishLatencies;
  uint64_t totalPublishes = 0;
  uint64_t totalNotifications = 0;
  uint64_t totalDataChanges = 0;
  uint64_t totalPublishErrors = 0;
  std::map<std::string, uint64_t> publishErrorStatuses;
  std::vector<double> allNotificationLatencies;
  uint64_t latFromServer = 0, latFromSource = 0, latNoStamp = 0;
  std::vector<double> allNewestLatencies;

  for (auto& metrics : sessionMetrics)
  {
    allPublishLatencies.insert(
      allPublishLatencies.end(), metrics.publishLatencies.begin(), metrics.publishLatencies.end());
    totalPublishes += metrics.totalPublishes;
    totalNotifications += metrics.totalNotificationMessages;
    totalDataChanges += metrics.totalDataChanges;
    totalPublishErrors += metrics.publishErrors;
    for (const auto& [status, count] : metrics.publishErrorStatuses)
      publishErrorStatuses[status] += count;
    allNotificationLatencies.insert(allNotificationLatencies.end(),
      metrics.notificationLatencies.begin(),
      metrics.notificationLatencies.end());
    allNewestLatencies.insert(
      allNewestLatencies.end(), metrics.newestLatencies.begin(), metrics.newestLatencies.end());
    latFromServer += metrics.latencyFromServerStamp;
    latFromSource += metrics.latencyFromSourceStamp;
    latNoStamp += metrics.latencyNoStamp;
  }

  auto publishStats = compute_stats(allPublishLatencies);
  double soakActualDuration = static_cast<double>(soakDuration);
  double changesPerSec = static_cast<double>(totalDataChanges) / soakActualDuration;
  double messagesPerSec = static_cast<double>(totalNotifications) / soakActualDuration;

  log.info("Publish stats: publishes={} errors={} notif_msgs={} ({:.0f}/s) data_changes={} ({:.0f}/s)",
    totalPublishes,
    totalPublishErrors,
    totalNotifications,
    messagesPerSec,
    totalDataChanges,
    changesPerSec);
  log.info("  Data changes per publish: {:.1f}",
    totalPublishes > 0 ? static_cast<double>(totalDataChanges) / static_cast<double>(totalPublishes) : 0.0);
  log.info("  Publish latency: p50={}us p99={}us max={}us",
    static_cast<int>(publishStats.p50Us),
    static_cast<int>(publishStats.p99Us),
    static_cast<int>(publishStats.maxUs));

  auto churnStats = compute_stats(churnLatencies);
  if (churnEnabled)
  {
    log.info("Churn stats: {} operations, p50={}us p99={}us",
      churnOps,
      static_cast<int>(churnStats.p50Us),
      static_cast<int>(churnStats.p99Us));
  }

  // Delete all subscriptions and close sessions.
  for (auto& state : sessions)
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    for (auto& sub : state->subscriptions)
    {
      try
      {
        delete_subscription(state->handle->session, sub);
      }
      catch (...)
      {}
    }
    state->subscriptions.clear();

    try
    {
      state->handle->session.close_sync();
      state->handle->channel.close_sync();
    }
    catch (...)
    {}
  }

  // Build summary JSON.
  boost::json::object subscriptionLoad;
  subscriptionLoad["sessions"] = sessionCount;
  subscriptionLoad["subscriptions_per_session"] = subsPerSession;
  subscriptionLoad["monitored_items_per_subscription"] = itemsPerSub;
  subscriptionLoad["total_monitored_items"] = totalItems;
  subscriptionLoad["items_created"] = totalItemsCreated;
  subscriptionLoad["items_rejected"] = totalItemsRejected;
  subscriptionLoad["granted_sampling_ms"] = grantedSamplingMs;
  subscriptionLoad["granted_publishing_ms"] = grantedPublishingMs;
  subscriptionLoad["expected_samples_per_sec"] = expectedSamplesPerSec;
  subscriptionLoad["distinct_granted_intervals"] = static_cast<uint64_t>(grantedIntervals.size());
  {
    boost::json::array iv;
    for (double v : grantedIntervals)
      iv.push_back(v);
    subscriptionLoad["granted_interval_set"] = std::move(iv);
  }

  boost::json::object setupObj;
  setupObj["subscription_create_latency"] = stats_to_json(subCreateStats);
  setupObj["monitored_items_create_latency"] = stats_to_json(monCreateStats);
  setupObj["total_setup_time_s"] = setupElapsed;
  subscriptionLoad["setup"] = std::move(setupObj);

  boost::json::object publishSoakObj;
  publishSoakObj["duration_s"] = static_cast<double>(soakDuration);
  publishSoakObj["total_publishes"] = static_cast<int64_t>(totalPublishes);
  // Messages and data changes are different quantities and both are reported:
  // an earlier version counted NotificationData structures and called them
  // notifications, which understated delivered changes by the batching factor.
  publishSoakObj["total_notification_messages"] = static_cast<int64_t>(totalNotifications);
  publishSoakObj["notification_messages_per_sec"] = messagesPerSec;
  publishSoakObj["total_data_changes"] = static_cast<int64_t>(totalDataChanges);
  publishSoakObj["data_changes_per_sec"] = changesPerSec;
  {
    boost::json::object statusObj;
    for (const auto& [status, count] : publishErrorStatuses)
      statusObj[status] = count;
    publishSoakObj["publish_error_statuses"] = std::move(statusObj);
  }
  if (allNotificationLatencies.empty() && (latNoStamp > 0))
  {
    log.info("  Notification latency: no usable timestamps on {} responses", latNoStamp);
    publishSoakObj["notification_latency_no_stamp"] = latNoStamp;
  }
  if (!allNotificationLatencies.empty())
  {
    auto latStats = compute_stats(allNotificationLatencies);
    boost::json::object latObj;
    latObj["samples"] = static_cast<uint64_t>(allNotificationLatencies.size());
    latObj["p50_us"] = latStats.p50Us;
    latObj["p95_us"] = latStats.p95Us;
    latObj["p99_us"] = latStats.p99Us;
    latObj["max_us"] = latStats.maxUs;
    latObj["min_us"] = latStats.minUs;
    latObj["from_server_timestamp"] = latFromServer;
    latObj["from_source_timestamp"] = latFromSource;
    latObj["no_timestamp"] = latNoStamp;
    latObj["clock_offset_us"] = std::chrono::duration<double, std::micro>(clockOffset).count();
    if (!allNewestLatencies.empty())
    {
      auto nStats = compute_stats(allNewestLatencies);
      boost::json::object nObj;
      nObj["p50_us"] = nStats.p50Us;
      nObj["p99_us"] = nStats.p99Us;
      nObj["min_us"] = nStats.minUs;
      nObj["max_us"] = nStats.maxUs;
      nObj["samples"] = static_cast<uint64_t>(allNewestLatencies.size());
      latObj["newest_in_response"] = std::move(nObj);
      log.info("  Newest-in-response latency: p50={:.0f}us p99={:.0f}us", nStats.p50Us, nStats.p99Us);
    }
    publishSoakObj["notification_latency"] = std::move(latObj);
    log.info("  Notification latency: p50={:.0f}us p95={:.0f}us p99={:.0f}us max={:.0f}us (n={})",
      latStats.p50Us,
      latStats.p95Us,
      latStats.p99Us,
      latStats.maxUs,
      allNotificationLatencies.size());
  }
  publishSoakObj["data_changes_per_publish"] =
    totalPublishes > 0 ? static_cast<double>(totalDataChanges) / static_cast<double>(totalPublishes) : 0.0;
  publishSoakObj["publish_errors"] = static_cast<int64_t>(totalPublishErrors);
  publishSoakObj["publish_latency"] = stats_to_json(publishStats);
  subscriptionLoad["publish_soak"] = std::move(publishSoakObj);

  boost::json::object churnObj;
  churnObj["enabled"] = churnEnabled;
  churnObj["operations"] = static_cast<int64_t>(churnOps);
  if (churnEnabled && churnOps > 0)
  {
    churnObj["churn_latency"] = stats_to_json(churnStats);
  }
  subscriptionLoad["churn"] = std::move(churnObj);

  summary["subscription_load"] = std::move(subscriptionLoad);

  log.info("Subscription stress test complete");
}

}  // namespace

PerfMode parse_perf_mode(const std::string& s)
{
  if (s == "throughput")
    return PerfMode::Throughput;
  if (s == "latency")
    return PerfMode::Latency;
  if (s == "soak")
    return PerfMode::Soak;
  if (s == "concurrency")
    return PerfMode::Concurrency;
  if (s == "subscription")
    return PerfMode::Subscription;
  if (s == "all")
    return PerfMode::All;
  throw std::runtime_error("Unknown perf mode: " + s);
}

void run_perf_tests(const FuzzerConfig& config, PerfMode mode, const ua::Logger& logger)
{
  auto log = logger.with_category("perf");
  log.info("Starting performance tests");

  // Before anything derives a NodeId from it: the generator reads from whatever namespace it was
  // told, which is not 1 when the server is serving the static array namespace.
  gGeneratedNodeNs = config.performance.readNamespace;

  gReadNodeId = ua::NodeId(config.performance.readNodeNs, config.performance.readNodeId);
  gReadNodePool = config.performance.readNodeIds;
  gNodesPerRead = config.performance.nodesPerRead > 0 ? config.performance.nodesPerRead : 1;
  gGeneratedNodeCount = config.performance.generateNodes;
  if (gGeneratedNodeCount > 0)
  {
    gReadNodeId = ua::NodeId(gGeneratedNodeNs, generatedNodeBase);
    log.info("Reading {} node(s) per request from {} generated nodes in ns={}",
      gNodesPerRead,
      gGeneratedNodeCount,
      gGeneratedNodeNs);
  }
  if (!gReadNodePool.empty())
  {
    log.info("Read node pool: {} distinct nodes, one per session", gReadNodePool.size());
  }
  log.info("Measuring reads of ns={};i={}", config.performance.readNodeNs, config.performance.readNodeId);

  PerfServerFixture fixture(config.performance.serverThreads,
    config.performance.attachEndpoint,
    "127.0.0.1:0",
    config.performance.relaxConnectionThrottling);
  fixture.start();

  if (fixture.attached())
    log.info("Driving an external server at {}", fixture.endpointUrl);
  else
    log.info("Server executor pool: {} thread(s)", fixture.serverThreads);

  log.info("Server listening on {}", fixture.endpointUrl);

  auto outputDir = config.reporting.outputDir;
  std::filesystem::create_directories(outputDir);

  boost::json::object summary;
  summary["server_endpoint"] = fixture.endpointUrl;
  // When the server is elsewhere, this block describes the load generator, not
  // the thing being measured: the server writes its own alongside it.
  summary["host"] = describe_host(fixture.attached() ? 0 : fixture.serverThreads);
  summary["host_role"] = fixture.attached() ? "client" : "client+server";
  summary["attached"] = fixture.attached();
  summary["connection_throttling_relaxed"] = config.performance.relaxConnectionThrottling;
  summary["read_node"] = boost::json::object{{"ns", config.performance.readNodeNs},
    {"i", config.performance.readNodeId},
    {"pool_size", static_cast<uint64_t>(config.performance.readNodeIds.size())},
    {"nodes_per_read", gNodesPerRead},
    {"generated_nodes", gGeneratedNodeCount}};

  if (mode == PerfMode::Throughput || mode == PerfMode::All)
  {
    run_throughput_test(fixture, config, summary, outputDir, log);
  }

  if (mode == PerfMode::Latency || mode == PerfMode::All)
  {
    run_latency_profile_test(fixture, config, summary, outputDir, log);
  }

  if (mode == PerfMode::Soak || mode == PerfMode::All)
  {
    run_soak_test(fixture, config, summary, outputDir, log);
  }

  if (mode == PerfMode::Concurrency || mode == PerfMode::All)
  {
    run_concurrency_test(fixture, config, summary, log);
  }

  if (mode == PerfMode::Subscription || mode == PerfMode::All)
  {
    run_subscription_stress_test(fixture, config, summary, log);
  }

  // Write summary JSON.
  auto summaryPath = outputDir + "/perf_summary.json";
  std::ofstream out(summaryPath);
  out << ua::json_helpers::pretty_json(summary);

  log.info("Results written to {}", summaryPath);

  fixture.stop();

  log.info("Complete");
}

namespace
{
std::atomic<bool> gPerfServerStop{false};

extern "C" void perf_server_signal_handler(int)
{
  gPerfServerStop.store(true);
}
}  // namespace

void run_probe_nodes(
  const FuzzerConfig& config, uint16_t ns, uint32_t from, uint32_t to, const ua::Logger& logger)
{
  auto log = logger.with_category("probe");

  PerfServerFixture fixture(1, config.performance.attachEndpoint);
  fixture.start();

  auto client = fixture.make_client();
  auto channel = client.core().open_channel_sync(fixture.channel_config());
  auto session = channel.create_session_sync({});
  session.activate_sync();

  std::vector<uint32_t> good;
  for (uint32_t id = from; id <= to; ++id)
  {
    if (issue_read(session, ua::NodeId(ns, id)).ok)
      good.push_back(id);
  }

  std::string list;
  for (size_t i = 0; i < good.size(); ++i)
  {
    list += (i ? "," : "") + std::to_string(good[i]);
  }
  log.info("readable variable nodes in ns={} [{}..{}]: {} of {}", ns, from, to, good.size(), to - from + 1);
  std::cout << "PROBE_GOOD " << list << "\n";

  session.close_sync();
  channel.close_sync();
  fixture.stop();
}

void run_perf_server(const FuzzerConfig& config, const ua::Logger& logger)
{
  auto log = logger.with_category("perf-serve");

  PerfServerFixture fixture(config.performance.serverThreads,
    {},
    config.performance.listenAddress,
    config.performance.relaxConnectionThrottling,
    config.performance.throttleMaxConnsPerIp,
    config.performance.throttleAttemptsPerMin,
    config.performance.maxConnections,
    config.performance.maxSecureChannels,
    config.performance.maxSessions,
    config.performance.generateNodes,
    config.performance.maxMonitoredItems,
    config.performance.maxMonitoredItemsPerSub,
    config.performance.maxMonitoredItemsPerCall);
  fixture.staticNamespace = config.performance.staticNamespace;
  fixture.start();

  log.info("Serving {} with {} executor thread(s)", fixture.endpointUrl, fixture.serverThreads);
  if (fixture.generateNodes > 0)
  {
    log.info("Generated {} of {} requested scalar nodes in ns={} from i={}",
      fixture.generatedNodes,
      fixture.generateNodes,
      gGeneratedNodeNs,
      generatedNodeBase);
  }

  auto outputDir = config.reporting.outputDir;
  std::filesystem::create_directories(outputDir);

  // The load generator is on another machine, so its /proc says nothing about
  // this process. Record what the server ran on, and watch its own memory.
  boost::json::object hostDoc;
  hostDoc["host"] = describe_host(fixture.serverThreads);
  hostDoc["endpoint"] = fixture.endpointUrl;
  hostDoc["host_role"] = "server";
  // Part of the conditions: a relaxed throttle changes what a capacity figure means.
  hostDoc["connection_throttling_relaxed"] = config.performance.relaxConnectionThrottling;
  hostDoc["anonymous_role_grant"] = "Observer";
  hostDoc["max_connections"] = config.performance.maxConnections;
  hostDoc["max_secure_channels"] = config.performance.maxSecureChannels;
  hostDoc["max_sessions"] = config.performance.maxSessions;
  hostDoc["generated_nodes"] = fixture.generatedNodes;
  hostDoc["max_monitored_items"] = config.performance.maxMonitoredItems;
  hostDoc["max_monitored_items_per_sub"] = config.performance.maxMonitoredItemsPerSub;
  hostDoc["max_monitored_items_per_call"] = config.performance.maxMonitoredItemsPerCall;
  {
    std::ofstream out(outputDir + "/perf_server_host.json");
    out << ua::json_helpers::pretty_json(hostDoc);
  }

  std::ofstream csv(outputDir + "/server_rss_over_time.csv");
  csv << "elapsed_s,rss_kib,open_fds\n";

  std::signal(SIGINT, perf_server_signal_handler);
  std::signal(SIGTERM, perf_server_signal_handler);

  log.info("Sampling to {}/server_rss_over_time.csv; SIGINT or SIGTERM to stop", outputDir);

  const auto start = std::chrono::steady_clock::now();
  while (!gPerfServerStop.load())
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    auto rss = read_self_rss_kib();
    auto fds = count_open_fds();
    csv << static_cast<int64_t>(elapsed) << "," << (rss ? static_cast<int64_t>(*rss) : -1) << ","
        << (fds ? static_cast<int64_t>(*fds) : -1) << "\n";
    csv.flush();
  }

  log.info("Signalled; stopping");
  fixture.stop();
  log.info("Complete");
}

}  // namespace fuzz
