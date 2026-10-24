// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_PERF_TESTER_H
#define FUZZ_PERF_TESTER_H

#include "fuzzer_config.h"

#include "ua_logger.h"

#include <string>

namespace fuzz
{

enum class PerfMode
{
  Throughput,
  Latency,
  Soak,
  Concurrency,
  Subscription,
  All
};

PerfMode parse_perf_mode(const std::string& s);

/// Run performance tests against an in-process server.
/// Writes results to perf_summary.json and CSV files in the output directory.
void run_perf_tests(const FuzzerConfig& config, PerfMode mode, const ua::Logger& logger);

/// Serve an endpoint for a load generator running elsewhere, until signalled.
///
/// Samples this process's own RSS and descriptor count while it runs: with the
/// client on another machine, nothing on the client side can observe the
/// server's memory behaviour.
void run_perf_server(const FuzzerConfig& config, const ua::Logger& logger);

/// Read each numeric NodeId in [from, to] once against an external server and
/// print those that answer Good, so a distinct-node measurement can be built from
/// nodes known to be readable rather than assumed to be.
void run_probe_nodes(const FuzzerConfig& config, uint16_t ns, uint32_t from, uint32_t to,
  const ua::Logger& logger);

}  // namespace fuzz

#endif  // !FUZZ_PERF_TESTER_H
