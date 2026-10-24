// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "campaign.h"

#include "baseline.h"
#include "channel_layer_harness.h"
#include "message_layer_harness.h"
#include "monitor.h"
#include "raw_tcp_harness.h"
#include "reporter.h"
#include "service_layer_harness.h"
#include "transport_layer_harness.h"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <filesystem>

#include <map>
#include <numeric>
#include <random>

namespace fuzz
{

namespace
{

/// Weighted layer scheduler per spec 4.4.
class LayerScheduler
{
public:
  explicit LayerScheduler(const std::vector<FuzzLayer>& layers, std::mt19937_64& rng) : mRng(rng)
  {
    for (auto layer : layers)
    {
      mWeights[layer] = 1.0;
      mCaseCounts[layer] = 0;
      mFindingCounts[layer] = 0;
    }
  }

  FuzzLayer select()
  {
    rebalance();

    // 10% exploration budget: pick uniformly at random.
    auto exploreDist = std::uniform_real_distribution<double>(0.0, 1.0);
    if (exploreDist(mRng) < 0.1)
    {
      auto layers = active_layers();
      auto idx = std::uniform_int_distribution<size_t>(0, layers.size() - 1)(mRng);
      return layers[idx];
    }

    // Weighted selection.
    double totalWeight = 0.0;
    for (auto& [layer, weight] : mWeights)
    {
      totalWeight += weight;
    }

    auto dist = std::uniform_real_distribution<double>(0.0, totalWeight);
    double pick = dist(mRng);

    double cumulative = 0.0;
    for (auto& [layer, weight] : mWeights)
    {
      cumulative += weight;
      if (pick <= cumulative)
      {
        return layer;
      }
    }

    // Fallback.
    return mWeights.begin()->first;
  }

  void record_case(FuzzLayer layer)
  {
    ++mCaseCounts[layer];
  }

  void record_finding(FuzzLayer layer)
  {
    ++mFindingCounts[layer];
    // Layers that produce findings get 3x weight.
    mWeights[layer] = 3.0;
  }

  uint64_t total_cases() const
  {
    uint64_t total = 0;
    for (auto& [_, count] : mCaseCounts)
    {
      total += count;
    }
    return total;
  }

private:
  void rebalance()
  {
    auto total = total_cases();
    if (total == 0)
      return;

    // Layers that received < 5% of total cases get weight boosted.
    double threshold = static_cast<double>(total) * 0.05;
    for (auto& [layer, count] : mCaseCounts)
    {
      if (static_cast<double>(count) < threshold)
      {
        mWeights[layer] = std::max(mWeights[layer], 2.0);
      }
    }

    // Decay finding-boosted weights over time.
    for (auto& [layer, weight] : mWeights)
    {
      if (weight > 1.0)
      {
        weight = std::max(1.0, weight * 0.999);
      }
    }
  }

  std::vector<FuzzLayer> active_layers() const
  {
    std::vector<FuzzLayer> layers;
    for (auto& [layer, _] : mWeights)
    {
      layers.push_back(layer);
    }
    return layers;
  }

  std::mt19937_64& mRng;
  std::map<FuzzLayer, double> mWeights;
  std::map<FuzzLayer, uint64_t> mCaseCounts;
  std::map<FuzzLayer, uint64_t> mFindingCounts;
};

// Signal handler state for crash isolation.
volatile std::sig_atomic_t gCrashDetected = 0;

void crash_signal_handler(int sig)
{
  gCrashDetected = sig;
}

/// Run a single layer's harness with a per-layer case budget.
void run_layer_batch(
  FuzzLayer layer, FuzzerConfig layerConfig, Reporter& reporter, Monitor& monitor, const ua::Logger& logger)
{
  switch (layer)
  {
  case FuzzLayer::Service:
    run_service_layer_harness(layerConfig, reporter, monitor, logger);
    break;
  case FuzzLayer::MessageEncoding:
    run_message_layer_harness(layerConfig, reporter, monitor, logger);
    break;
  case FuzzLayer::SecureChannel:
    run_channel_layer_harness(layerConfig, reporter, monitor, logger);
    break;
  case FuzzLayer::TransportFraming:
    run_transport_layer_harness(layerConfig, reporter, monitor, logger);
    break;
  case FuzzLayer::Raw:
    run_raw_tcp_harness(layerConfig, reporter, monitor, logger);
    break;
  }
}

FuzzResult aggregate_result(const FuzzerConfig& config, const Reporter& reporter, const Monitor& monitor,
  double elapsedSec, uint64_t totalCases)
{
  FuzzResult result;
  result.totalCases = totalCases;
  // R13: the rejection tally travels with the findings, so the oracle can assert what the SDK DID
  // with each mutation and not only that nothing went wrong while it did it.
  result.acceptedMutations = monitor.accepted_mutations();
  result.rejectedMutations = monitor.rejected_mutations();
  result.elapsedSeconds = elapsedSec;
  result.casesPerSecond = elapsedSec > 0 ? static_cast<double>(totalCases) / elapsedSec : 0.0;
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

  return result;
}

}  // namespace

FuzzResult run_campaign(const FuzzerConfig& config, const ua::Logger& logger)
{
  auto log = logger.with_category("campaign");

  log.info("Starting fuzzing campaign");
  {
    std::string layerList;
    for (size_t i = 0; i < config.campaign.layers.size(); ++i)
    {
      if (i > 0)
        layerList += ", ";
      layerList += to_string(config.campaign.layers[i]);
    }
    log.info("Layers: {}", layerList);
  }
  log.info(
    "Max cases: {}", config.campaign.maxCases == 0 ? "unlimited" : std::to_string(config.campaign.maxCases));

  // Set up reporter and monitor.
  Reporter reporter(config.reporting, logger);
  Monitor monitor(config);

  // Load or run baseline if available.
  auto baselinePath = config.reporting.outputDir + "/baseline.json";
  auto baseline = load_baseline(baselinePath, logger);
  if (baseline)
  {
    log.info("Loaded baseline from {}", baselinePath);
    monitor.set_baseline(*baseline);
  }

  // Install signal handlers for crash isolation.
  auto prevSigsegv = std::signal(SIGSEGV, crash_signal_handler);
  auto prevSigabrt = std::signal(SIGABRT, crash_signal_handler);

  // Set up RNG.
  auto seed = config.campaign.rngSeed != 0 ? config.campaign.rngSeed : std::random_device{}();
  std::mt19937_64 rng(seed);
  log.info("RNG seed: {}", seed);

  // Set up scheduler.
  LayerScheduler scheduler(config.campaign.layers, rng);

  auto startTime = std::chrono::steady_clock::now();
  auto maxCases = config.campaign.maxCases;

  // Each batch runs a small number of cases per layer dispatch to allow
  // interleaving between layers.
  constexpr uint64_t batchSize = 50;

  uint64_t casesDispatched = 0;

  while (maxCases == 0 || casesDispatched < maxCases)
  {
    // Check for signal-based crash.
    if (gCrashDetected != 0)
    {
      Finding f;
      f.findingClass = FindingClass::SecurityCrash;
      f.severity = FindingSeverity::Critical;
      f.caseNumber = casesDispatched;
      f.description = "Process caught signal " + std::to_string(gCrashDetected);
      reporter.report_finding(f);
      gCrashDetected = 0;

      // Reset monitor state and continue.
      monitor.set_server_alive(true);
    }

    // Select layer.
    auto layer = scheduler.select();

    // Compute batch size for this layer.
    auto remaining = maxCases > 0 ? maxCases - casesDispatched : batchSize;
    auto batchCases = std::min(remaining, batchSize);

    // Create a per-batch config with the selected layer and batch case count.
    auto batchConfig = config;
    batchConfig.campaign.layers = {layer};
    batchConfig.campaign.maxCases = batchCases;
    batchConfig.campaign.rngSeed = rng();

    auto findingsBefore = reporter.finding_count();

    log.debug("Batch: {} cases on {}", batchCases, to_string(layer));

    try
    {
      run_layer_batch(layer, batchConfig, reporter, monitor, logger);
    }
    catch (const std::exception& e)
    {
      log.error("Layer {} threw: {}", to_string(layer), e.what());

      Finding f;
      f.findingClass = FindingClass::BehaviourUnhandledException;
      f.severity = FindingSeverity::High;
      f.layer = layer;
      f.caseNumber = casesDispatched;
      f.description = std::string("Layer harness exception: ") + e.what();
      reporter.report_finding(f);
    }

    casesDispatched += batchCases;
    scheduler.record_case(layer);

    auto findingsAfter = reporter.finding_count();
    if (findingsAfter > findingsBefore)
    {
      scheduler.record_finding(layer);
    }

    // Status update.
    auto elapsed = std::chrono::steady_clock::now() - startTime;
    auto elapsedSec = std::chrono::duration<double>(elapsed).count();
    auto rate = elapsedSec > 0 ? static_cast<double>(casesDispatched) / elapsedSec : 0.0;
    reporter.update_status(casesDispatched, rate, layer, monitor.server_alive());

    // Reset server alive for next batch.
    monitor.set_server_alive(true);
  }

  // Restore signal handlers.
  std::signal(SIGSEGV, prevSigsegv);
  std::signal(SIGABRT, prevSigabrt);

  auto totalElapsed = std::chrono::steady_clock::now() - startTime;
  auto totalSec = std::chrono::duration<double>(totalElapsed).count();

  auto result = aggregate_result(config, reporter, monitor, totalSec, casesDispatched);
  reporter.write_summary(result);

  log.info("Complete. {} cases in {}s ({} cases/sec)",
    casesDispatched,
    static_cast<int>(totalSec),
    static_cast<int>(result.casesPerSecond));
  log.info("Findings: {} total (security={} crashes={} memory={} perf={})",
    reporter.finding_count(),
    result.securityFindings,
    result.crashes,
    result.memoryLeaks,
    result.perfFindings);

  return result;
}

}  // namespace fuzz
