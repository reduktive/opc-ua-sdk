// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_MESSAGE_LAYER_HARNESS_H
#define FUZZ_MESSAGE_LAYER_HARNESS_H

#include "fuzzer_config.h"
#include "monitor.h"
#include "reporter.h"

#include "ua_logger.h"

namespace fuzz
{

/// Run the Layer 4 (message encoding) fuzz harness.
/// Starts an in-process server, connects a client with a FuzzSecurityPolicy
/// interceptor, generates valid service requests, mutates the encoded bytes
/// before they hit the wire, and observes the server's response.
void run_message_layer_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger);

}  // namespace fuzz

#endif  // !FUZZ_MESSAGE_LAYER_HARNESS_H
