// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fuzzer_config.h"

#include <boost/json.hpp>
#include <fstream>
#include <iostream>
#include <sstream>

namespace fuzz
{

namespace
{

FuzzLayer parse_layer(const std::string& s)
{
  if (s == "raw")
    return FuzzLayer::Raw;
  if (s == "transport")
    return FuzzLayer::TransportFraming;
  if (s == "channel")
    return FuzzLayer::SecureChannel;
  if (s == "message")
    return FuzzLayer::MessageEncoding;
  if (s == "service")
    return FuzzLayer::Service;
  throw std::runtime_error("Unknown layer: " + s);
}

FuzzService parse_service(const std::string& s)
{
  if (s == "read")
    return FuzzService::Read;
  if (s == "browse")
    return FuzzService::Browse;
  if (s == "browse_next")
    return FuzzService::BrowseNext;
  if (s == "write")
    return FuzzService::Write;
  if (s == "call")
    return FuzzService::Call;
  if (s == "translate_browse_paths")
    return FuzzService::TranslateBrowsePaths;
  if (s == "register_nodes")
    return FuzzService::RegisterNodes;
  if (s == "unregister_nodes")
    return FuzzService::UnregisterNodes;
  if (s == "create_subscription")
    return FuzzService::CreateSubscription;
  if (s == "modify_subscription")
    return FuzzService::ModifySubscription;
  if (s == "delete_subscriptions")
    return FuzzService::DeleteSubscriptions;
  if (s == "set_publishing_mode")
    return FuzzService::SetPublishingMode;
  if (s == "create_monitored_items")
    return FuzzService::CreateMonitoredItems;
  if (s == "modify_monitored_items")
    return FuzzService::ModifyMonitoredItems;
  if (s == "delete_monitored_items")
    return FuzzService::DeleteMonitoredItems;
  if (s == "set_monitoring_mode")
    return FuzzService::SetMonitoringMode;
  if (s == "add_nodes")
    return FuzzService::AddNodes;
  if (s == "add_references")
    return FuzzService::AddReferences;
  if (s == "delete_nodes")
    return FuzzService::DeleteNodes;
  if (s == "delete_references")
    return FuzzService::DeleteReferences;
  if (s == "find_servers")
    return FuzzService::FindServers;
  if (s == "get_endpoints")
    return FuzzService::GetEndpoints;
  throw std::runtime_error("Unknown service: " + s);
}

std::string get_string(const boost::json::object& obj, const char* key, const std::string& def)
{
  auto it = obj.find(key);
  if (it == obj.end())
    return def;
  return std::string(it->value().as_string());
}

uint64_t get_uint64(const boost::json::object& obj, const char* key, uint64_t def)
{
  auto it = obj.find(key);
  if (it == obj.end())
    return def;
  return static_cast<uint64_t>(it->value().as_int64());
}

uint32_t get_uint32(const boost::json::object& obj, const char* key, uint32_t def)
{
  return static_cast<uint32_t>(get_uint64(obj, key, def));
}

double get_double(const boost::json::object& obj, const char* key, double def)
{
  auto it = obj.find(key);
  if (it == obj.end())
    return def;
  return it->value().as_double();
}

bool get_bool(const boost::json::object& obj, const char* key, bool def)
{
  auto it = obj.find(key);
  if (it == obj.end())
    return def;
  return it->value().as_bool();
}

}  // namespace

FuzzerConfig load_config(const std::string& path)
{
  std::ifstream file(path);
  if (!file.is_open())
  {
    throw std::runtime_error("Cannot open config file: " + path);
  }

  std::ostringstream ss;
  ss << file.rdbuf();
  auto jv = boost::json::parse(ss.str());
  auto& root = jv.as_object();

  FuzzerConfig cfg;

  if (auto it = root.find("target"); it != root.end())
  {
    auto& t = it->value().as_object();
    cfg.target.endpoint = get_string(t, "endpoint", cfg.target.endpoint);
    cfg.target.timeoutMs = get_uint32(t, "timeout_ms", cfg.target.timeoutMs);
    cfg.target.outOfProcess = get_bool(t, "out_of_process", cfg.target.outOfProcess);
  }

  if (auto it = root.find("campaign"); it != root.end())
  {
    auto& c = it->value().as_object();
    cfg.campaign.maxCases = get_uint64(c, "max_cases", cfg.campaign.maxCases);
    cfg.campaign.seedCorpusDir = get_string(c, "seed_corpus_dir", cfg.campaign.seedCorpusDir);
    cfg.campaign.rngSeed = get_uint64(c, "rng_seed", cfg.campaign.rngSeed);

    if (auto lit = c.find("layers"); lit != c.end())
    {
      cfg.campaign.layers.clear();
      for (auto& v : lit->value().as_array())
      {
        auto s = std::string(v.as_string());
        if (s == "all")
        {
          cfg.campaign.layers = {FuzzLayer::Raw,
            FuzzLayer::TransportFraming,
            FuzzLayer::SecureChannel,
            FuzzLayer::MessageEncoding,
            FuzzLayer::Service};
          break;
        }
        cfg.campaign.layers.push_back(parse_layer(s));
      }
    }

    if (auto sit = c.find("services"); sit != c.end())
    {
      cfg.campaign.services.clear();
      for (auto& v : sit->value().as_array())
      {
        auto s = std::string(v.as_string());
        if (s != "all")
        {
          cfg.campaign.services.push_back(parse_service(s));
        }
      }
    }
  }

  if (auto it = root.find("limits"); it != root.end())
  {
    auto& l = it->value().as_object();
    cfg.limits.maxMessageSize = get_uint32(l, "max_message_size", cfg.limits.maxMessageSize);
    cfg.limits.maxStringLen = get_uint32(l, "max_string_len", cfg.limits.maxStringLen);
    cfg.limits.maxArrayLen = get_uint32(l, "max_array_len", cfg.limits.maxArrayLen);
    cfg.limits.maxNestingDepth = get_uint32(l, "max_nesting_depth", cfg.limits.maxNestingDepth);
  }

  if (auto it = root.find("sync_block"); it != root.end())
  {
    auto& s = it->value().as_object();
    cfg.syncBlock.serverThreads =
      static_cast<int>(get_uint32(s, "server_threads", static_cast<uint32_t>(cfg.syncBlock.serverThreads)));
    cfg.syncBlock.detectSyncBlock = get_bool(s, "detect_sync_block", cfg.syncBlock.detectSyncBlock);
    cfg.syncBlock.livenessDeadlineMs =
      get_uint32(s, "liveness_deadline_ms", cfg.syncBlock.livenessDeadlineMs);
    cfg.syncBlock.heartbeatIntervalMs =
      get_uint32(s, "heartbeat_interval_ms", cfg.syncBlock.heartbeatIntervalMs);
  }

  if (auto it = root.find("baseline"); it != root.end())
  {
    auto& b = it->value().as_object();
    cfg.baseline.samples = get_uint32(b, "samples", cfg.baseline.samples);
    cfg.baseline.latencyAlertMul = get_double(b, "latency_alert_mul", cfg.baseline.latencyAlertMul);
    cfg.baseline.latencyWarnMul = get_double(b, "latency_warn_mul", cfg.baseline.latencyWarnMul);
  }

  if (auto it = root.find("performance"); it != root.end())
  {
    auto& p = it->value().as_object();
    cfg.performance.soakDurationS = get_uint32(p, "soak_duration_s", cfg.performance.soakDurationS);
    cfg.performance.loadSteps = get_uint32(p, "load_steps", cfg.performance.loadSteps);

    if (auto cit = p.find("concurrency_steps"); cit != p.end())
    {
      cfg.performance.concurrencySteps.clear();
      for (auto& v : cit->value().as_array())
      {
        cfg.performance.concurrencySteps.push_back(static_cast<uint32_t>(v.as_int64()));
      }
    }

    if (auto rit = p.find("read_nodes"); rit != p.end())
    {
      cfg.performance.readNodeIds.clear();
      for (auto& v : rit->value().as_array())
      {
        cfg.performance.readNodeIds.push_back(static_cast<uint32_t>(v.as_int64()));
      }
    }

    if (auto tit = p.find("throughput_concurrency"); tit != p.end())
    {
      cfg.performance.throughputConcurrency.clear();
      for (auto& v : tit->value().as_array())
      {
        cfg.performance.throughputConcurrency.push_back(static_cast<uint32_t>(v.as_int64()));
      }
    }

    cfg.performance.subscriptionSessionCount =
      get_uint32(p, "subscription_session_count", cfg.performance.subscriptionSessionCount);
    cfg.performance.subscriptionsPerSession =
      get_uint32(p, "subscriptions_per_session", cfg.performance.subscriptionsPerSession);
    cfg.performance.monitoredItemsPerSubscription =
      get_uint32(p, "monitored_items_per_subscription", cfg.performance.monitoredItemsPerSubscription);
    cfg.performance.subscriptionSoakDurationS =
      get_uint32(p, "subscription_soak_duration_s", cfg.performance.subscriptionSoakDurationS);
    cfg.performance.subscriptionChurnEnabled =
      get_bool(p, "subscription_churn_enabled", cfg.performance.subscriptionChurnEnabled);
  }

  if (auto it = root.find("reporting"); it != root.end())
  {
    auto& r = it->value().as_object();
    cfg.reporting.console = get_bool(r, "console", cfg.reporting.console);
    cfg.reporting.file = get_bool(r, "file", cfg.reporting.file);
    cfg.reporting.outputDir = get_string(r, "output_dir", cfg.reporting.outputDir);
    cfg.reporting.corpusOutDir = get_string(r, "corpus_out_dir", cfg.reporting.corpusOutDir);
    cfg.reporting.logAllResponses = get_bool(r, "log_all_responses", cfg.reporting.logAllResponses);
    cfg.reporting.saveAllCases = get_bool(r, "save_all_cases", cfg.reporting.saveAllCases);
    cfg.reporting.consoleUpdateHz = get_uint32(r, "console_update_hz", cfg.reporting.consoleUpdateHz);
  }

  return cfg;
}

void print_config(const FuzzerConfig& config)
{
  std::cout << "Target:\n";
  std::cout << "  endpoint:       " << config.target.endpoint << "\n";
  std::cout << "  timeout_ms:     " << config.target.timeoutMs << "\n";
  std::cout << "  out_of_process: " << (config.target.outOfProcess ? "true" : "false") << "\n";

  std::cout << "Campaign:\n";
  std::cout << "  max_cases:      " << config.campaign.maxCases << "\n";
  std::cout << "  layers:         ";
  for (size_t i = 0; i < config.campaign.layers.size(); ++i)
  {
    if (i > 0)
      std::cout << ", ";
    std::cout << to_string(config.campaign.layers[i]);
  }
  std::cout << "\n";
  std::cout << "  rng_seed:       " << config.campaign.rngSeed << "\n";

  std::cout << "Limits:\n";
  std::cout << "  max_message_size: " << config.limits.maxMessageSize << "\n";
  std::cout << "  max_string_len:   " << config.limits.maxStringLen << "\n";
  std::cout << "  max_array_len:    " << config.limits.maxArrayLen << "\n";

  std::cout << "Baseline:\n";
  std::cout << "  samples:          " << config.baseline.samples << "\n";

  std::cout << "Performance:\n";
  std::cout << "  soak_duration_s:        " << config.performance.soakDurationS << "\n";
  std::cout << "  load_steps:             " << config.performance.loadSteps << "\n";
  std::cout << "  throughput_concurrency:  ";
  for (size_t i = 0; i < config.performance.throughputConcurrency.size(); ++i)
  {
    if (i > 0)
      std::cout << ", ";
    std::cout << config.performance.throughputConcurrency[i];
  }
  std::cout << "\n";
  std::cout << "  subscription_session_count:  " << config.performance.subscriptionSessionCount << "\n";
  std::cout << "  subscriptions_per_session:   " << config.performance.subscriptionsPerSession << "\n";
  std::cout << "  monitored_items_per_sub:     " << config.performance.monitoredItemsPerSubscription << "\n";
  std::cout << "  subscription_soak_duration_s:" << config.performance.subscriptionSoakDurationS << "\n";
  std::cout << "  subscription_churn_enabled:  "
            << (config.performance.subscriptionChurnEnabled ? "true" : "false") << "\n";

  std::cout << "Reporting:\n";
  std::cout << "  output_dir:       " << config.reporting.outputDir << "\n";
  std::cout << "  console:          " << (config.reporting.console ? "true" : "false") << "\n";
  std::cout << "  file:             " << (config.reporting.file ? "true" : "false") << "\n";
}

}  // namespace fuzz
