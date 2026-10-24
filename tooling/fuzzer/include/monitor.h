// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_MONITOR_H
#define FUZZ_MONITOR_H

#include "fuzz_types.h"
#include "fuzzer_config.h"

#include <chrono>
#include <deque>
#include <map>
#include <optional>
#include <string>

namespace fuzz
{

struct BaselineData;

class Monitor
{
public:
  explicit Monitor(const FuzzerConfig& config);

  /// Set baseline data for anomaly detection. When set, the monitor compares
  /// latencies against baseline thresholds and flags spikes.
  void set_baseline(const BaselineData& baseline);

  struct CaseOutcome
  {
    uint64_t caseNumber{0};
    FuzzLayer layer{FuzzLayer::Service};
    FuzzService service{FuzzService::Read};
    uint32_t statusCode{0};
    std::chrono::microseconds latency{0};
    bool connectionDropped{false};
    bool timedOut{false};
    bool exceptionThrown{false};
    std::string exceptionMessage;
  };

  /// Record the outcome of a fuzz case. Returns a Finding if the outcome is anomalous.
  std::optional<Finding> record(const CaseOutcome& outcome);

  /// Check if the server is still alive (based on recent outcomes).
  bool server_alive() const
  {
    return mServerAlive;
  }

  /// Mark server as alive/dead explicitly.
  void set_server_alive(bool alive)
  {
    mServerAlive = alive;
  }

  /// Get the average latency over recent cases.
  double average_latency_us() const;

  /// How many mutated cases the SDK ACCEPTED -- answered with a Good status, without dropping the
  /// connection, timing out or throwing (the R13 acceptance condition).
  ///
  /// The campaign's oracle asserted `crashes == 0` and `securityFindings == 0`, and every finding
  /// class those two count is a robustness class: a crash, a hang, an unexpected disconnect, an
  /// ASan violation, a DoS degradation. **A mutated request the SDK answers `Good` produced no
  /// finding of any kind**, so a client that accepts a mis-signed response without crashing passed.
  /// That is what made `fuzz:` discharge nothing.
  ///
  /// Acceptance is counted rather than failed, because not every mutation must be rejected -- a
  /// bit-flip inside a payload can still yield a well-formed request. What the oracle can now do,
  /// and could not before, is state the rejection rate and assert against it.
  uint64_t accepted_mutations() const
  {
    return mAcceptedMutations;
  }

  /// How many mutated cases the SDK rejected: a Bad or Uncertain status, a drop, a timeout, or a
  /// throw. Reported beside the acceptances so the two account for every case.
  uint64_t rejected_mutations() const
  {
    return mRejectedMutations;
  }

private:
  void tally_outcome(const CaseOutcome& outcome, bool rejected);

  std::optional<Finding> check_baseline_anomaly(const CaseOutcome& outcome) const;

  uint64_t mAcceptedMutations{0};
  uint64_t mRejectedMutations{0};

  FuzzerConfig mConfig;
  bool mServerAlive{true};
  std::deque<std::chrono::microseconds> mRecentLatencies;
  static constexpr size_t sMaxRecentLatencies{100};

  /// Per-service baseline thresholds (service name -> alert/warn threshold in us).
  struct BaselineThresholds
  {
    double alertThresholdUs{0.0};
    double warnThresholdUs{0.0};
  };

  std::map<std::string, BaselineThresholds> mBaselineThresholds;
  bool mHasBaseline{false};
};

}  // namespace fuzz

#endif  // !FUZZ_MONITOR_H
