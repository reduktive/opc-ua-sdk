// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_SERVICE_LAYER_HARNESS_H
#define FUZZ_SERVICE_LAYER_HARNESS_H

#include "fuzzer_config.h"
#include "monitor.h"
#include "reporter.h"

#include "ua_logger.h"

namespace fuzz
{

/// Run the Layer 5 (service API) fuzz harness.
/// Starts an in-process server, connects a client, and sends fuzzed
/// requests through the public session API for all service types including
/// subscription lifecycle (create/modify/delete subscriptions and monitored items).
void run_service_layer_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger);

}  // namespace fuzz

#endif  // !FUZZ_SERVICE_LAYER_HARNESS_H
