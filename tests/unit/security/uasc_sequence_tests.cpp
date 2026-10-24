// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_stack_utilities.h"

#include <cstdint>

using namespace ua;
using namespace ua::stack_utils;

namespace
{

struct SeqCase
{
  const char* name;
  uint32_t previous;
  uint32_t received;
  bool expectedPass;
  uint32_t expectedPrevious;
};

}  // namespace

TEST(UascSequenceTests, TestAndSetSequenceNo_ExactIncrementOnly)
{
  const SeqCase cases[] = {
    {"accepts +1 from 0", 0u, 1u, true, 1u},
    {"rejects duplicate", 7u, 7u, false, 7u},
    {"rejects skip", 7u, 9u, false, 7u},

    // Current implementation relies on unsigned overflow semantics.
    {"wrap boundary: max -> 0", 0xFFFFFFFFu, 0u, true, 0u},
  };

  for (const auto& tc : cases)
  {
    SCOPED_TRACE(tc.name);
    auto previous = tc.previous;
    EXPECT_EQ(test_and_set_sequence_no(previous, tc.received), tc.expectedPass);
    EXPECT_EQ(previous, tc.expectedPrevious);
  }
}

TEST(UascSequenceTests, LegacyTestAndSetSequenceNo_AllowsWrapOnlyToLowRange)
{
  const SeqCase cases[] = {
    {"accepts +1 normal", 100u, 101u, true, 101u},
    {"rejects skip normal", 100u, 102u, false, 100u},

    {"near wrap: allows +1", 0xFFFFFFFEu, 0xFFFFFFFFu, true, 0xFFFFFFFFu},

    // When previous > (max - 1024), implementation allows wrap to received < 1024.
    {"near wrap: allows wrap to 0", 0xFFFFFFF5u, 0u, true, 0u},
    {"near wrap: allows wrap to 1023", 0xFFFFFFF5u, 1023u, true, 1023u},
    {"near wrap: rejects wrap to 1024", 0xFFFFFFF5u, 1024u, false, 0xFFFFFFF5u},
  };

  for (const auto& tc : cases)
  {
    SCOPED_TRACE(tc.name);
    auto previous = tc.previous;
    EXPECT_EQ(legacy_test_and_set_sequence_no(previous, tc.received), tc.expectedPass);
    EXPECT_EQ(previous, tc.expectedPrevious);
  }
}
