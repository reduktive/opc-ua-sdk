// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "campaign.h"
#include "fuzz_types.h"
#include "fuzzer_config.h"
#include "ua_logger.h"

#include <gtest/gtest.h>

#include <cstdio>

namespace
{

fuzz::FuzzerConfig make_test_config(std::vector<fuzz::FuzzLayer> layers, uint64_t maxCases)
{
  fuzz::FuzzerConfig config;
  config.campaign.layers = std::move(layers);
  config.campaign.maxCases = maxCases;
  config.campaign.rngSeed = 42;
  config.target.timeoutMs = 2000;
  config.reporting.console = false;
  config.reporting.file = false;
  return config;
}

}  // namespace

namespace
{

/// Assert what the SDK DID with each mutation, not merely that nothing went wrong while it did it.
///
/// `qa_remediation_plan.md` R13. The `crashes` / `securityFindings` pair above every call to this
/// measures ROBUSTNESS: every finding class those two count is a crash, a hang, an unexpected
/// disconnect, an ASan violation or a DoS degradation. A mutated request the SDK answers `Good`
/// produces none of them - so a server that accepted everything passed both, and `fuzz:` discharged
/// nothing.
///
/// Two assertions, and the second is a ratchet rather than a zero:
///
///  * **The tally accounts for every case.** accepted + rejected == total. This is what proves the
///    counter is wired at all; without it a silently-zero counter would satisfy any ceiling.
///  * **Acceptance may not RISE.** Not every mutation must be rejected - a bit-flip inside an
///    already-decoded request can yield a well-formed one, and mutating a NodeId in a Read yields a
///    valid Read of a different node. Asserting zero would be a false alarm on legitimate
///    behaviour. What matters is the direction: a rise means the SDK started accepting inputs it
///    used to refuse, and that is a finding whatever the absolute number is.
///
/// The ceilings below are measured, not chosen. They are this tree's rates on 2026-08-09 and they
/// may only shrink.
void expect_rejection_accounted(const fuzz::FuzzResult& result, uint64_t acceptedCeiling)
{
  EXPECT_EQ(result.acceptedMutations + result.rejectedMutations, result.totalCases)
    << "the rejection tally does not account for every case - the counter is not wired";
  // Reported on every run, pass or fail: the rate IS the oracle's output, and a number only
  // printed when it breaches tells nobody how close it was.
  std::fprintf(stderr,
    "[R13] accepted %llu / %llu (ceiling %llu)\n",
    (unsigned long long)result.acceptedMutations,
    (unsigned long long)result.totalCases,
    (unsigned long long)acceptedCeiling);
  EXPECT_LE(result.acceptedMutations, acceptedCeiling)
    << "the SDK answered Good to more mutated requests than it used to (" << result.acceptedMutations
    << " of " << result.totalCases
    << "). A fuzz oracle that does not assert this is asserting "
       "survival, not rejection";
}

}  // namespace

TEST(FuzzCampaign, ServiceLayer_NoCrashes)
{
  auto config = make_test_config({fuzz::FuzzLayer::Service}, 100);
  auto result = fuzz::run_campaign(config, ua::Logger{});

  EXPECT_EQ(result.crashes, 0u);
  EXPECT_EQ(result.securityFindings, 0u);
  EXPECT_EQ(result.totalCases, 100u);
  expect_rejection_accounted(result, 79);
}

TEST(FuzzCampaign, MessageLayer_NoCrashes)
{
  auto config = make_test_config({fuzz::FuzzLayer::MessageEncoding}, 50);
  auto result = fuzz::run_campaign(config, ua::Logger{});

  EXPECT_EQ(result.crashes, 0u);
  EXPECT_EQ(result.securityFindings, 0u);
  expect_rejection_accounted(result, 1);
}

TEST(FuzzCampaign, ChannelLayer_NoCrashes)
{
  auto config = make_test_config({fuzz::FuzzLayer::SecureChannel}, 50);
  auto result = fuzz::run_campaign(config, ua::Logger{});

  EXPECT_EQ(result.crashes, 0u);
  EXPECT_EQ(result.securityFindings, 0u);
  expect_rejection_accounted(result, 11);
}

TEST(FuzzCampaign, MultiLayer_NoCrashes)
{
  auto config = make_test_config({fuzz::FuzzLayer::Service, fuzz::FuzzLayer::MessageEncoding}, 100);
  auto result = fuzz::run_campaign(config, ua::Logger{});

  EXPECT_EQ(result.crashes, 0u);
  EXPECT_EQ(result.securityFindings, 0u);
  expect_rejection_accounted(result, 79);
}

TEST(FuzzCampaign, ServiceLayer_AllServices_NoCrashes)
{
  // Exercises subscription lifecycle: create subs, monitored items, publish, modify, delete.
  auto config = make_test_config({fuzz::FuzzLayer::Service}, 200);
  auto result = fuzz::run_campaign(config, ua::Logger{});

  EXPECT_EQ(result.crashes, 0u);
  EXPECT_EQ(result.securityFindings, 0u);
  EXPECT_EQ(result.totalCases, 200u);
  expect_rejection_accounted(result, 154);
}

TEST(FuzzCampaign, ServiceLayer_SubscriptionStress_NoCrashes)
{
  auto config = make_test_config({fuzz::FuzzLayer::Service}, 300);
  config.campaign.rngSeed = 12345;
  auto result = fuzz::run_campaign(config, ua::Logger{});

  EXPECT_EQ(result.crashes, 0u);
  EXPECT_EQ(result.securityFindings, 0u);
  EXPECT_EQ(result.totalCases, 300u);
  expect_rejection_accounted(result, 234);
}
