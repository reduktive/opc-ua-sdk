// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_BASELINE_H
#define FUZZ_BASELINE_H

#include "fuzzer_config.h"

#include "ua_logger.h"

#include <map>
#include <optional>
#include <string>

namespace fuzz
{

/// Per-service latency statistics from baseline profiling.
struct LatencyStats
{
  double minUs{0.0};
  double meanUs{0.0};
  double p95Us{0.0};
  double p99Us{0.0};
  double stddevUs{0.0};
};

/// Per-service baseline data.
struct ServiceBaseline
{
  LatencyStats latency;
  uint32_t expectedStatus{0};
  double alertThresholdUs{0.0};
  double warnThresholdUs{0.0};
};

/// Connection/handshake baseline data.
struct ConnectionBaseline
{
  double handshakeMeanUs{0.0};
  double handshakeP99Us{0.0};
};

/// Full baseline data for a server.
struct BaselineData
{
  std::string recordedAt;
  std::string serverEndpoint;
  uint32_t samplesPerService{0};
  std::map<std::string, ServiceBaseline> services;
  ConnectionBaseline connection;
};

/// Run baseline profiling against an in-process server.
/// Sends N requests per service, measures latency distributions and handshake timing.
/// Writes baseline.json to the output directory.
BaselineData run_baseline(const FuzzerConfig& config, const ua::Logger& logger);

/// Load baseline from a JSON file. Returns nullopt if file doesn't exist.
std::optional<BaselineData> load_baseline(const std::string& path, const ua::Logger& logger);

/// Save baseline to a JSON file.
void save_baseline(const BaselineData& baseline, const std::string& path);

}  // namespace fuzz

#endif  // !FUZZ_BASELINE_H
