// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "baseline.h"
#include "campaign.h"
#include "fuzz_types.h"
#include "fuzzer_config.h"
#include "perf_tester.h"

#include "ua_log_sink_implementations.h"
#include "ua_logger.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace
{

struct CliArgs
{
  enum class Mode
  {
    Fuzz,
    Baseline,
    Perf,
    PerfServe,
    ProbeNodes,
    PrintConfig
  };

  Mode mode{Mode::Fuzz};
  std::string configPath;
  std::vector<std::string> layers;
  std::vector<std::string> services;
  std::string perfMode{"all"};
  std::string endpoint;
  std::string listenAddress;
  bool relaxThrottling{false};
  uint32_t throttleMaxConns{0};
  std::string readNode;
  std::string probeSpec;
  uint32_t generateNodes{0};
  uint32_t nodesPerRead{0};
  uint32_t staticNamespace{0};
  uint32_t readNamespace{0};
  double subPublishingMs{0.0};
  double subSamplingMs{0.0};
  bool subGeneratedNodes{false};
  std::string subIntervalSet;
  uint32_t subMaxNotifPerPublish{0};
  bool subMeasureLatency{false};
  uint32_t maxMonItems{0};
  uint32_t maxMonItemsPerSub{0};
  uint32_t maxMonItemsPerCall{0};
  uint32_t subSessions{0};
  uint32_t subPerSession{0};
  uint32_t subItems{0};
  uint32_t maxConnections{0};
  uint32_t maxSecureChannels{0};
  uint32_t maxSessions{0};
  uint32_t throttleAttemptsPerMin{0};
  uint64_t maxCases{0};
  uint64_t rngSeed{0};
  uint32_t soakDuration{0};
  int serverThreads{0};
  uint32_t livenessDeadlineMs{0};
  bool maxCasesSet{false};
  bool rngSeedSet{false};
  bool soakDurationSet{false};
  bool serverThreadsSet{false};
  bool detectSyncBlock{false};
  bool livenessDeadlineMsSet{false};
};

void print_usage()
{
  std::cout
    << "Usage: opcua-fuzzer [options]\n"
    << "\n"
    << "Modes:\n"
    << "  --fuzz           Run fuzzing campaign (default)\n"
    << "  --baseline       Run baseline profiling\n"
    << "  --perf           Run performance tests\n"
    << "  --perf-serve     Serve an endpoint for a load generator on another machine\n"
    << "  --probe-nodes <ns>,<from>,<to>  Report which numeric NodeIds answer Good\n"
    << "  --print-config   Print effective config and exit\n"
    << "\n"
    << "Options:\n"
    << "  --config <path>  Load config from JSON file\n"
    << "  --layers <list>  Comma-separated layers: raw,transport,channel,message,service,all\n"
    << "  --services <list> Comma-separated services to fuzz\n"
    << "  --max-cases <n>  Maximum number of fuzz cases\n"
    << "  --rng-seed <n>   RNG seed for reproducibility\n"
    << "  --perf-mode <m>  Performance test mode: throughput,latency,soak,concurrency,subscription,all\n"
    << "  --soak-duration <s> Soak test duration in seconds\n"
    << "  --server-threads <n> Server executor threads (1 = single-threaded server)\n"
    << "  --endpoint <url> Drive an already-running server instead of starting one\n"
    << "  --listen <addr>  Bind address for --perf-serve (default 127.0.0.1:0)\n"
    << "  --relax-throttling  Raise per-IP connection limits (capacity runs; recorded in results)\n"
    << "  --read-node <ns>,<i>  Numeric NodeId the load generator reads (default 0,2258)\n"
    << "  --generate-nodes <n>  Create n simple scalar nodes in ns=1 and read those\n"
    << "  --nodes-per-read <n>  NodesToRead per Read request (default 1)\n"
    << "  --static-namespace [one-node]  Serve the generated nodes from a lock-free array of\n"
    << "                        immutable scalars instead of the default namespace. 'one-node'\n"
    << "                        resolves every identifier to a single node, putting all reference\n"
    << "                        counting on one cache line. Server side.\n"
    << "  --read-ns <n>         Namespace index the generator reads from (default 1). Needed with\n"
    << "                        --static-namespace, which does not land at 1.\n"
    << "  --sub-publishing-interval <ms>  Subscription publishing interval\n"
    << "  --sub-sampling-interval <ms>    MonitoredItem sampling interval (0 = publishing interval)\n"
    << "  --sub-generated-nodes           Monitor generated scalars instead of CurrentTime\n"
    << "  --sub-interval-set <a,b,c>      Sampling intervals rotated across subscriptions\n"
    << "  --sub-max-notif-per-publish <n> MaxNotificationsPerPublish (0 = unlimited)\n"
    << "  --sub-measure-latency           Measure notification delivery latency\n"
    << "  --max-monitored-items <n>          Server MaxMonitoredItems (0 = default 10000)\n"
    << "  --max-monitored-items-per-sub <n>  Per-subscription cap (0 = default 1000)\n"
    << "  --max-monitored-items-per-call <n> Per-call cap (0 = default 1000)\n"
    << "  --sub-sessions <n> --sub-per-session <n> --sub-items <n>  Subscription load shape\n"
    << "  --max-connections <n>     Server MaxConnections for a capacity run (0 = default 100)\n"
    << "  --max-secure-channels <n> Server MaxSecureChannels (0 = default 100)\n"
    << "  --max-sessions <n>        Server MaxSessions (0 = default 100)\n"
    << "  --throttle-max-conns <n>       Per-IP concurrent connection cap (0 = default)\n"
    << "  --throttle-attempts-per-min <n> Per-IP connection attempt rate cap (0 = default)\n"
    << "  --detect-sync-block  Fail if a handler blocks the (single) server thread synchronously\n"
    << "  --liveness-deadline-ms <n> Heartbeat deadline for --detect-sync-block (default 2000)\n"
    << "  --help           Show this help\n";
}

std::vector<std::string> split(const std::string& s, char delim)
{
  std::vector<std::string> result;
  std::istringstream stream(s);
  std::string token;
  while (std::getline(stream, token, delim))
  {
    if (!token.empty())
    {
      result.push_back(token);
    }
  }
  return result;
}

CliArgs parse_args(int argc, char* argv[])
{
  CliArgs args;

  for (int i = 1; i < argc; ++i)
  {
    std::string arg = argv[i];

    if (arg == "--help" || arg == "-h")
    {
      print_usage();
      std::exit(0);
    }
    else if (arg == "--fuzz")
    {
      args.mode = CliArgs::Mode::Fuzz;
    }
    else if (arg == "--baseline")
    {
      args.mode = CliArgs::Mode::Baseline;
    }
    else if (arg == "--perf")
    {
      args.mode = CliArgs::Mode::Perf;
    }
    else if (arg == "--throttle-max-conns" && i + 1 < argc)
    {
      args.throttleMaxConns = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--throttle-attempts-per-min" && i + 1 < argc)
    {
      args.throttleAttemptsPerMin = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--max-connections" && i + 1 < argc)
    {
      args.maxConnections = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--max-secure-channels" && i + 1 < argc)
    {
      args.maxSecureChannels = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--max-sessions" && i + 1 < argc)
    {
      args.maxSessions = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--generate-nodes" && i + 1 < argc)
    {
      args.generateNodes = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--static-namespace")
    {
      // Optional mode word: "one-node" puts every identifier on a single control block.
      args.staticNamespace = 1;
      if (i + 1 < argc && std::string_view{argv[i + 1]} == "one-node")
      {
        args.staticNamespace = 2;
        ++i;
      }
    }
    else if (arg == "--read-ns" && i + 1 < argc)
    {
      args.readNamespace = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--sub-publishing-interval" && i + 1 < argc)
    {
      args.subPublishingMs = std::stod(argv[++i]);
    }
    else if (arg == "--sub-sampling-interval" && i + 1 < argc)
    {
      args.subSamplingMs = std::stod(argv[++i]);
    }
    else if (arg == "--max-monitored-items" && i + 1 < argc)
    {
      args.maxMonItems = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--max-monitored-items-per-sub" && i + 1 < argc)
    {
      args.maxMonItemsPerSub = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--max-monitored-items-per-call" && i + 1 < argc)
    {
      args.maxMonItemsPerCall = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--sub-max-notif-per-publish" && i + 1 < argc)
    {
      args.subMaxNotifPerPublish = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--sub-measure-latency")
    {
      args.subMeasureLatency = true;
    }
    else if (arg == "--sub-interval-set" && i + 1 < argc)
    {
      args.subIntervalSet = argv[++i];
    }
    else if (arg == "--sub-generated-nodes")
    {
      args.subGeneratedNodes = true;
    }
    else if (arg == "--sub-sessions" && i + 1 < argc)
    {
      args.subSessions = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--sub-per-session" && i + 1 < argc)
    {
      args.subPerSession = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--sub-items" && i + 1 < argc)
    {
      args.subItems = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--nodes-per-read" && i + 1 < argc)
    {
      args.nodesPerRead = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    else if (arg == "--read-node" && i + 1 < argc)
    {
      args.readNode = argv[++i];
    }
    else if (arg == "--relax-throttling")
    {
      args.relaxThrottling = true;
    }
    else if (arg == "--perf-serve")
    {
      args.mode = CliArgs::Mode::PerfServe;
    }
    else if (arg == "--probe-nodes" && i + 1 < argc)
    {
      args.mode = CliArgs::Mode::ProbeNodes;
      args.probeSpec = argv[++i];
    }
    else if (arg == "--endpoint" && i + 1 < argc)
    {
      args.endpoint = argv[++i];
    }
    else if (arg == "--listen" && i + 1 < argc)
    {
      args.listenAddress = argv[++i];
    }
    else if (arg == "--print-config")
    {
      args.mode = CliArgs::Mode::PrintConfig;
    }
    else if (arg == "--config" && i + 1 < argc)
    {
      args.configPath = argv[++i];
    }
    else if (arg == "--layers" && i + 1 < argc)
    {
      args.layers = split(argv[++i], ',');
    }
    else if (arg == "--services" && i + 1 < argc)
    {
      args.services = split(argv[++i], ',');
    }
    else if (arg == "--max-cases" && i + 1 < argc)
    {
      args.maxCases = std::stoull(argv[++i]);
      args.maxCasesSet = true;
    }
    else if (arg == "--rng-seed" && i + 1 < argc)
    {
      args.rngSeed = std::stoull(argv[++i]);
      args.rngSeedSet = true;
    }
    else if (arg == "--perf-mode" && i + 1 < argc)
    {
      args.perfMode = argv[++i];
    }
    else if (arg == "--soak-duration" && i + 1 < argc)
    {
      args.soakDuration = static_cast<uint32_t>(std::stoull(argv[++i]));
      args.soakDurationSet = true;
    }
    else if (arg == "--server-threads" && i + 1 < argc)
    {
      args.serverThreads = static_cast<int>(std::stoll(argv[++i]));
      args.serverThreadsSet = true;
    }
    else if (arg == "--detect-sync-block")
    {
      args.detectSyncBlock = true;
    }
    else if (arg == "--liveness-deadline-ms" && i + 1 < argc)
    {
      args.livenessDeadlineMs = static_cast<uint32_t>(std::stoull(argv[++i]));
      args.livenessDeadlineMsSet = true;
    }
    else
    {
      std::cerr << "Unknown option: " << arg << "\n";
      print_usage();
      std::exit(1);
    }
  }

  return args;
}

fuzz::FuzzLayer parse_layer_name(const std::string& s)
{
  if (s == "raw")
    return fuzz::FuzzLayer::Raw;
  if (s == "transport")
    return fuzz::FuzzLayer::TransportFraming;
  if (s == "channel")
    return fuzz::FuzzLayer::SecureChannel;
  if (s == "message")
    return fuzz::FuzzLayer::MessageEncoding;
  if (s == "service")
    return fuzz::FuzzLayer::Service;
  throw std::runtime_error("Unknown layer: " + s);
}

void apply_cli_overrides(fuzz::FuzzerConfig& config, const CliArgs& args)
{
  if (!args.layers.empty())
  {
    config.campaign.layers.clear();
    for (const auto& l : args.layers)
    {
      if (l == "all")
      {
        config.campaign.layers = {fuzz::FuzzLayer::Raw,
          fuzz::FuzzLayer::TransportFraming,
          fuzz::FuzzLayer::SecureChannel,
          fuzz::FuzzLayer::MessageEncoding,
          fuzz::FuzzLayer::Service};
        break;
      }
      config.campaign.layers.push_back(parse_layer_name(l));
    }
  }

  if (args.maxCasesSet)
  {
    config.campaign.maxCases = args.maxCases;
  }

  if (args.rngSeedSet)
  {
    config.campaign.rngSeed = args.rngSeed;
  }

  if (args.soakDurationSet)
  {
    config.performance.soakDurationS = args.soakDuration;
  }

  if (args.serverThreadsSet)
  {
    config.syncBlock.serverThreads = args.serverThreads;
    config.performance.serverThreads =
      args.serverThreads > 0 ? static_cast<uint32_t>(args.serverThreads) : 0U;
  }

  if (!args.endpoint.empty())
  {
    config.performance.attachEndpoint = args.endpoint;
  }

  if (args.relaxThrottling)
  {
    config.performance.relaxConnectionThrottling = true;
  }

  if (!args.readNode.empty())
  {
    auto comma = args.readNode.find(',');
    if (comma == std::string::npos)
    {
      std::cerr << "--read-node expects <ns>,<i>\n";
      std::exit(1);
    }
    config.performance.readNodeNs = static_cast<uint16_t>(std::stoul(args.readNode.substr(0, comma)));
    config.performance.readNodeId = static_cast<uint32_t>(std::stoul(args.readNode.substr(comma + 1)));
  }

  config.performance.generateNodes = args.generateNodes;
  config.performance.staticNamespace = args.staticNamespace;
  if (args.readNamespace != 0)
  {
    config.performance.readNamespace = static_cast<uint16_t>(args.readNamespace);
  }
  config.performance.subPublishingIntervalMs = args.subPublishingMs;
  config.performance.subSamplingIntervalMs = args.subSamplingMs;
  config.performance.subUseGeneratedNodes = args.subGeneratedNodes;
  if (args.subMaxNotifPerPublish != 0)
  {
    config.performance.subMaxNotificationsPerPublish = args.subMaxNotifPerPublish;
  }
  if (args.subMeasureLatency)
  {
    config.performance.subMeasureLatency = true;
  }
  if (!args.subIntervalSet.empty())
  {
    config.performance.subIntervalSet.clear();
    std::string spec = args.subIntervalSet;
    size_t pos = 0;
    while (!spec.empty())
    {
      pos = spec.find(',');
      auto tok = spec.substr(0, pos);
      if (!tok.empty())
        config.performance.subIntervalSet.push_back(std::stod(tok));
      if (pos == std::string::npos)
        break;
      spec.erase(0, pos + 1);
    }
  }
  config.performance.maxMonitoredItems = args.maxMonItems;
  config.performance.maxMonitoredItemsPerSub = args.maxMonItemsPerSub;
  config.performance.maxMonitoredItemsPerCall = args.maxMonItemsPerCall;
  if (args.subSessions > 0)
    config.performance.subscriptionSessionCount = args.subSessions;
  if (args.subPerSession > 0)
    config.performance.subscriptionsPerSession = args.subPerSession;
  if (args.subItems > 0)
    config.performance.monitoredItemsPerSubscription = args.subItems;
  if (args.nodesPerRead > 0)
    config.performance.nodesPerRead = args.nodesPerRead;
  config.performance.maxConnections = args.maxConnections;
  config.performance.maxSecureChannels = args.maxSecureChannels;
  config.performance.maxSessions = args.maxSessions;
  config.performance.throttleMaxConnsPerIp = args.throttleMaxConns;
  config.performance.throttleAttemptsPerMin = args.throttleAttemptsPerMin;

  if (!args.listenAddress.empty())
  {
    config.performance.listenAddress = args.listenAddress;
  }

  if (args.detectSyncBlock)
  {
    config.syncBlock.detectSyncBlock = true;
  }

  if (args.livenessDeadlineMsSet)
  {
    config.syncBlock.livenessDeadlineMs = args.livenessDeadlineMs;
  }
}

}  // namespace

int main(int argc, char* argv[])
{
  auto args = parse_args(argc, argv);

  fuzz::FuzzerConfig config;
  if (!args.configPath.empty())
  {
    config = fuzz::load_config(args.configPath);
  }

  apply_cli_overrides(config, args);

  // Create logger with console sink.
  auto logLevel = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Info);
  auto logSink = std::make_shared<ua::ConsoleLogSink>();
  ua::Logger logger(logSink, logLevel, "fuzzer");

  switch (args.mode)
  {
  case CliArgs::Mode::PrintConfig:
    fuzz::print_config(config);
    return 0;

  case CliArgs::Mode::Fuzz:
  {
    auto result = fuzz::run_campaign(config, logger);
    return (result.crashes > 0) ? 1 : 0;
  }

  case CliArgs::Mode::Baseline:
  {
    auto baseline = fuzz::run_baseline(config, logger);
    logger.info(
      "Profiled {} services with {} samples each", baseline.services.size(), baseline.samplesPerService);
    return 0;
  }

  case CliArgs::Mode::Perf:
  {
    auto mode = fuzz::parse_perf_mode(args.perfMode);
    fuzz::run_perf_tests(config, mode, logger);
    return 0;
  }

  case CliArgs::Mode::PerfServe:
  {
    fuzz::run_perf_server(config, logger);
    return 0;
  }

  case CliArgs::Mode::ProbeNodes:
  {
    unsigned ns = 0, from = 0, to = 0;
    if (std::sscanf(args.probeSpec.c_str(), "%u,%u,%u", &ns, &from, &to) != 3)
    {
      std::cerr << "--probe-nodes expects <ns>,<from>,<to>\n";
      return 1;
    }
    fuzz::run_probe_nodes(config, static_cast<uint16_t>(ns), from, to, logger);
    return 0;
  }
  }

  return 0;
}
