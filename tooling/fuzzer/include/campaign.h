// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_CAMPAIGN_H
#define FUZZ_CAMPAIGN_H

#include "fuzz_types.h"
#include "fuzzer_config.h"

#include "ua_logger.h"

namespace fuzz
{

/// Run a full fuzzing campaign across configured layers with weighted scheduling,
/// crash isolation, baseline integration, and result aggregation.
/// Returns the aggregated result.
FuzzResult run_campaign(const FuzzerConfig& config, const ua::Logger& logger);

}  // namespace fuzz

#endif  // !FUZZ_CAMPAIGN_H
