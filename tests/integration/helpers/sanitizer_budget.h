// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#pragma once

#include <chrono>

// AddressSanitizer and ThreadSanitizer detection, across GCC (__SANITIZE_*) and Clang
// (__has_feature). Kept in one place so a budget never has to ask the question itself.
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define UA_TEST_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define UA_TEST_SANITIZED 1
#endif
#endif

namespace ua::test_utils
{

/// How much longer the same work takes in this build than in an ordinary one.
///
/// A sanitized build is not a slow machine, it is a different order of magnitude: instrumenting
/// every memory access or every synchronisation edge turns an integration test that runs in about
/// 1.5 seconds into one that runs in 12 to 19 (measured across the `gcc14-asan` integration shards,
/// 19 September 2026). Eight is the low end of that range, chosen so a budget is generous rather
/// than marginal - a budget that only just fits is a flake waiting for a busier runner.
///
/// This scales the room a test gives the server to answer in. It must never scale anything the test
/// is proving: a lifetime counter that resets still has to reset, a refusal still has to be refused,
/// and a budget that expires still has to fail the test.
constexpr int sanitizer_slowdown() noexcept
{
#if defined(UA_TEST_SANITIZED)
  return 8;
#else
  return 1;
#endif
}

/// The same duration, widened for this build. Identity in an ordinary build.
constexpr std::chrono::milliseconds scaled(std::chrono::milliseconds budget) noexcept
{
  return budget * sanitizer_slowdown();
}

/// The same interval in milliseconds, widened for this build. For protocol parameters - a publishing
/// interval, a session timeout - where the test derives its own deadlines from the revised value the
/// server returns, so widening the input widens everything downstream with it.
constexpr double scaled_ms(double milliseconds) noexcept
{
  return milliseconds * sanitizer_slowdown();
}

}  // namespace ua::test_utils
