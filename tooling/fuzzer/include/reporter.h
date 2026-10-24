// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_REPORTER_H
#define FUZZ_REPORTER_H

#include "fuzz_types.h"
#include "fuzzer_config.h"

#include "ua_logger.h"

#include <chrono>
#include <mutex>
#include <vector>

namespace fuzz
{

class Reporter
{
public:
  Reporter(const FuzzerConfig::Reporting& config, const ua::Logger& logger);

  /// Record a finding. Thread-safe.
  void report_finding(const Finding& finding);

  /// Update live status line. Thread-safe.
  void update_status(uint64_t totalCases, double casesPerSec, FuzzLayer currentLayer, bool serverAlive);

  /// Write run_summary.json at campaign end.
  void write_summary(const FuzzResult& result);

  /// Get all findings recorded so far.
  std::vector<Finding> findings() const;

  uint32_t finding_count() const;

private:
  void write_finding_files(const Finding& finding);
  void print_finding_console(const Finding& finding);

  FuzzerConfig::Reporting mConfig;
  ua::Logger mLogger;
  mutable std::mutex mMutex;
  std::vector<Finding> mFindings;
  uint32_t mNextFindingId{1};
  std::chrono::steady_clock::time_point mLastStatusUpdate;
};

}  // namespace fuzz

#endif  // !FUZZ_REPORTER_H
