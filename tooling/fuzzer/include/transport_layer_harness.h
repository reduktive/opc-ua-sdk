// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_TRANSPORT_LAYER_HARNESS_H
#define FUZZ_TRANSPORT_LAYER_HARNESS_H

#include "fuzzer_config.h"
#include "monitor.h"
#include "reporter.h"

#include "ua_logger.h"

namespace fuzz
{

/// Run the Layer 2 (transport framing) fuzz harness.
/// Starts an in-process server, connects a client with a FuzzTransportConnection
/// decorator that mutates outgoing transport frames (HEL/ACK/MSG) before they
/// reach the server.
void run_transport_layer_harness(
  const FuzzerConfig& config, Reporter& reporter, Monitor& monitor, const ua::Logger& logger);

}  // namespace fuzz

#endif  // !FUZZ_TRANSPORT_LAYER_HARNESS_H
