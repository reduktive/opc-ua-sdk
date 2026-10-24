// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_RAW_TCP_HARNESS_H
#define FUZZ_RAW_TCP_HARNESS_H

#include "fuzzer_config.h"
#include "monitor.h"
#include "reporter.h"

#include "ua_logger.h"

namespace fuzz
{

/// Run the Layer 1 (raw TCP) fuzz harness.
/// Starts an in-process server and sends arbitrary bytes over raw TCP sockets.
/// No SDK client is used - this tests the server's resilience to malformed data
/// at the lowest protocol level.
void run_raw_tcp_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger);

}  // namespace fuzz

#endif  // !FUZZ_RAW_TCP_HARNESS_H
