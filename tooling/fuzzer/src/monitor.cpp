// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "monitor.h"

#include "baseline.h"

namespace fuzz
{

Monitor::Monitor(const FuzzerConfig& config) : mConfig(config)
{}

void Monitor::set_baseline(const BaselineData& baseline)
{
  mBaselineThresholds.clear();
  for (const auto& [name, sb] : baseline.services)
  {
    mBaselineThresholds[name] = {sb.alertThresholdUs, sb.warnThresholdUs};
  }
  mHasBaseline = true;
}

void Monitor::tally_outcome(const CaseOutcome& outcome, bool rejected)
{
  rejected ? ++mRejectedMutations : ++mAcceptedMutations;
}

std::optional<Finding> Monitor::record(const CaseOutcome& outcome)
{
  // R13: what the case DID, before what went wrong with it. A drop, a timeout or a throw is a
  // rejection; so is any status carrying the Bad (0x80000000) or Uncertain (0x40000000) severity
  // bits. Everything else is the SDK having ACCEPTED a mutated input, which produced no finding of
  // any kind before this and is the case `fuzz:` exists to assert on.
  const bool rejected = outcome.connectionDropped || outcome.timedOut || outcome.exceptionThrown ||
                        ((outcome.statusCode & 0xC0000000u) != 0u);
  tally_outcome(outcome, rejected);

  // Track latency.
  mRecentLatencies.push_back(outcome.latency);
  if (mRecentLatencies.size() > sMaxRecentLatencies)
  {
    mRecentLatencies.pop_front();
  }

  // Check for crash/hang indicators.
  if (outcome.connectionDropped)
  {
    mServerAlive = false;

    Finding f;
    f.findingClass = FindingClass::SecurityUnexpectedDisconnect;
    f.severity = default_severity(f.findingClass);
    f.layer = outcome.layer;
    f.service = outcome.service;
    f.caseNumber = outcome.caseNumber;
    f.latencyUs = static_cast<uint64_t>(outcome.latency.count());
    f.connectionDropped = true;
    f.description = "Server closed connection unexpectedly";
    return f;
  }

  if (outcome.timedOut)
  {
    Finding f;
    f.findingClass = FindingClass::SecurityHang;
    f.severity = default_severity(f.findingClass);
    f.layer = outcome.layer;
    f.service = outcome.service;
    f.caseNumber = outcome.caseNumber;
    f.latencyUs = static_cast<uint64_t>(outcome.latency.count());
    f.description = "Server did not respond within timeout";
    return f;
  }

  if (outcome.exceptionThrown)
  {
    Finding f;
    f.findingClass = FindingClass::BehaviourUnhandledException;
    f.severity = default_severity(f.findingClass);
    f.layer = outcome.layer;
    f.service = outcome.service;
    f.caseNumber = outcome.caseNumber;
    f.latencyUs = static_cast<uint64_t>(outcome.latency.count());
    f.description = "Unhandled exception: " + outcome.exceptionMessage;
    return f;
  }

  // Check against baseline thresholds if available.
  if (mHasBaseline)
  {
    if (auto finding = check_baseline_anomaly(outcome))
    {
      return finding;
    }
  }

  return std::nullopt;
}

std::optional<Finding> Monitor::check_baseline_anomaly(const CaseOutcome& outcome) const
{
  auto serviceName = to_string(outcome.service);
  auto it = mBaselineThresholds.find(serviceName);
  if (it == mBaselineThresholds.end())
    return std::nullopt;

  auto latencyUs = static_cast<double>(outcome.latency.count());
  const auto& thresholds = it->second;

  if (latencyUs > thresholds.alertThresholdUs)
  {
    Finding f;
    f.findingClass = FindingClass::PerfLatencySpike;
    f.severity = FindingSeverity::Medium;
    f.layer = outcome.layer;
    f.service = outcome.service;
    f.caseNumber = outcome.caseNumber;
    f.latencyUs = static_cast<uint64_t>(outcome.latency.count());
    f.description = "Latency " + std::to_string(static_cast<int>(latencyUs)) + "us exceeds alert threshold " +
                    std::to_string(static_cast<int>(thresholds.alertThresholdUs)) + "us";
    return f;
  }

  return std::nullopt;
}

double Monitor::average_latency_us() const
{
  if (mRecentLatencies.empty())
    return 0.0;

  double sum = 0.0;
  for (const auto& l : mRecentLatencies)
  {
    sum += static_cast<double>(l.count());
  }
  return sum / static_cast<double>(mRecentLatencies.size());
}

}  // namespace fuzz
