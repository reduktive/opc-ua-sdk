// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_CHANNEL_LAYER_HARNESS_H
#define FUZZ_CHANNEL_LAYER_HARNESS_H

#include "fuzzer_config.h"
#include "monitor.h"
#include "reporter.h"

#include "ua_logger.h"

namespace fuzz
{

/// Run the Layer 3 (SecureChannel) fuzz harness.
/// Starts an in-process server, connects a client with a FuzzSecurityPolicy
/// interceptor, and exercises channel-level operations: OPN handshake, session
/// creation/activation, rapid open/close cycling, and sequence number manipulation.
void run_channel_layer_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger);

}  // namespace fuzz

#endif  // !FUZZ_CHANNEL_LAYER_HARNESS_H
