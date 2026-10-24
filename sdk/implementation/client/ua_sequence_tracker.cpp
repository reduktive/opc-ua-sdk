// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sequence_tracker.h"

#include <cstdint>

namespace ua::client::detail
{

SequenceTracker::SequenceTracker(std::uint32_t firstExpected) noexcept : mNextExpected(firstExpected)
{}

SequenceClass SequenceTracker::classify(std::uint32_t received) const noexcept
{
  if (received == 0)
  {
    return SequenceClass::Invalid;  // 0 is never a valid Publish sequence number (CL-SUB-002)
  }
  if (received == mNextExpected)
  {
    return SequenceClass::InOrder;
  }
  // Signed 32-bit distance: (received - mNextExpected) wraps modulo 2^32, and casting to int32 yields
  // the shortest signed distance (well-defined two's-complement conversion in C++20). A positive
  // distance means `received` is ahead (a gap - some were missed); negative means it is behind (a
  // replay). This stays correct across the max->1 wrap where a plain unsigned compare would misjudge.
  // A distance of exactly 2^31 is equidistant and is treated as behind; it is unreachable in practice
  // (sequence numbers advance by one per message, so a 2-billion gap cannot occur).
  const std::int32_t distance = static_cast<std::int32_t>(received - mNextExpected);
  return (distance > 0) ? SequenceClass::Gap : SequenceClass::Duplicate;
}

void SequenceTracker::advance_past(std::uint32_t received) noexcept
{
  // The successor of the maximum sequence number is 1, not 0 (CL-SUB-002 wrap rule).
  mNextExpected = (received == maxSequenceNumber) ? 1u : received + 1u;
}

std::uint32_t SequenceTracker::next_expected() const noexcept
{
  return mNextExpected;
}

bool should_deliver(SequenceClass classification) noexcept
{
  // InOrder and Gap deliver; Duplicate and Invalid drop (the pipeline's "no dispatch" contract, CL-SUB-002).
  return classification == SequenceClass::InOrder || classification == SequenceClass::Gap;
}

}  // namespace ua::client::detail
