// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "heap_watermark.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <iostream>
#include <utility>
#include <vector>

// Detect AddressSanitizer across GCC (__SANITIZE_ADDRESS__) and Clang
// (__has_feature(address_sanitizer)).
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UA_TEST_ASAN_ENABLED 1
#endif
#endif
#if !defined(UA_TEST_ASAN_ENABLED) && defined(__SANITIZE_ADDRESS__)
#define UA_TEST_ASAN_ENABLED 1
#endif

#if defined(UA_TEST_ASAN_ENABLED)
// `<sanitizer/allocator_interface.h>` declares __sanitizer_get_current_allocated_bytes().
// Clang/LLVM ships it; GCC does NOT (it ships only asan/lsan_interface.h) even though
// libasan exports the symbol. Include the header when present, otherwise declare the
// prototype ourselves - the symbol resolves against the linked ASan runtime either way.
#if defined(__has_include)
#if __has_include(<sanitizer/allocator_interface.h>)
#include <sanitizer/allocator_interface.h>
#define UA_TEST_HAVE_ALLOCATOR_INTERFACE_HEADER 1
#endif
#endif
#if !defined(UA_TEST_HAVE_ALLOCATOR_INTERFACE_HEADER)
#include <cstddef>
extern "C" size_t __sanitizer_get_current_allocated_bytes();
#endif
#elif defined(__GLIBC__)
#include <malloc.h>
#endif

namespace ua::test_helpers
{

size_t current_heap_bytes()
{
#if defined(UA_TEST_ASAN_ENABLED)
  // Precise live-allocation count under ASan: excludes freed blocks, so the
  // signal is dominated by genuine retained allocations.
  return __sanitizer_get_current_allocated_bytes();
#elif defined(__GLIBC__)
  // Release free top-of-heap pages first so transient fragmentation does not
  // inflate the in-use total, then report bytes in in-use chunks.
  ::malloc_trim(0);
  return static_cast<size_t>(::mallinfo2().uordblks);
#else
  // No supported measurement mechanism -> caller treats 0 as "unsupported".
  return 0;
#endif
}

// True only when current_heap_bytes() is a PRECISE live-allocation count (ASan): exact, excludes
// freed blocks, so a tight per-iteration byte gate is meaningful. The glibc mallinfo2 path is NOT
// precise enough to gate on: arena growth and fragmentation under a create/destroy churn move
// uordblks by hundreds of bytes per iteration - load-dependent noise that swamps a small real leak.
// Measured directly on the subscription create/delete loop: ASan reports ~22 B/iter (flat, oscillating
// around zero) while the SAME workload on mallinfo2 reports ~780-1604 B/iter of pure allocator
// fragmentation. So on the imprecise path we still RUN the loop (crash/hang coverage, and any exact
// instance-count pins the caller asserts) but do not assert the byte tolerance.
bool heap_measurement_is_precise()
{
#if defined(UA_TEST_ASAN_ENABLED)
  return true;
#else
  return false;
#endif
}

void expect_stable_heap(const std::function<void()>& cycle, size_t iterations, size_t warmup,
  size_t toleranceBytes, std::function<void()> settle)
{
  const auto runSettle = [&settle]()
  {
    if (settle)
      settle();
  };

  // 1. Adaptive warm-up. The SDK has slowly-warming BOUNDED caches (per-thread buffer pools,
  //    interned ids, lazily-grown free lists) that reach steady state only after many hundreds
  //    of cycles - far more than a small fixed warm-up. Left in the measured window that warming
  //    looks exactly like a leak (it was: a fixed warmup=5 produced a decaying 5-22 KB/cycle
  //    "growth" that vanished once the caches settled). So warm in batches until a batch's
  //    per-cycle growth drops to what the measured loop tolerates (tolerance/iterations) for two
  //    consecutive batches - i.e. the caches have settled. A genuine UNBOUNDED leak never settles,
  //    so the cap terminates warm-up and the measured loop below still catches it.
  const size_t batch = std::max<size_t>(warmup, 1);
  const size_t maxWarmupCycles = 2000;
  const double perCycleBudget =
    iterations > 0 ? static_cast<double>(toleranceBytes) / static_cast<double>(iterations) : 0.0;
  size_t warmedCycles = 0;
  size_t consecutiveSettled = 0;
  size_t prevHeap = current_heap_bytes();
  while (warmedCycles < maxWarmupCycles)
  {
    for (size_t i = 0; i < batch; ++i)
      cycle();
    warmedCycles += batch;
    runSettle();
    const size_t nowHeap = current_heap_bytes();
    const double batchPerCycle =
      nowHeap > prevHeap ? static_cast<double>(nowHeap - prevHeap) / static_cast<double>(batch) : 0.0;
    prevHeap = nowHeap;
    if (batchPerCycle <= perCycleBudget)
    {
      if (++consecutiveSettled >= 2)
        break;
    }
    else
    {
      consecutiveSettled = 0;
    }
  }

  // 2. Measured loop with PERIODIC SAMPLING + linear-regression slope.
  //
  //    Why not a single baseline-vs-after pair (the previous design): one before/after read of the
  //    heap counter is noisy. The glibc mallinfo2 path in particular wobbles with arena growth and
  //    fragmentation, and a single mistimed sample can push the endpoint past an absolute tolerance
  //    while the heap is flat *on average* - the observed flake was 313 KB "growth" vs a 256 KB
  //    tolerance, a one-off endpoint jump, failing across multiple non-ASan jobs under load.
  //
  //    Instead we sample the (settled) heap at many checkpoints across the loop and fit a
  //    least-squares line. The SLOPE is the sustained per-iteration trend, which is exactly what a
  //    leak is and a transient is not:
  //      - a settled bounded cache, a one-off arena jump, or measurement scatter  -> slope ~ 0  -> PASS
  //      - a genuine per-iteration leak                                           -> slope > 0  -> FAIL
  //    Averaging the trend over the whole run is both far less flaky than a single endpoint AND
  //    strictly more sensitive to a real, sustained leak. We settle before every sample so each
  //    reading is taken with async teardown drained (an in-flight-teardown offset that varied across
  //    samples would otherwise tilt the slope).
  const size_t sampleCount = std::min<size_t>(iterations, 12);

  std::vector<double> cycleAt;  // x: cumulative cycles completed at each sample
  std::vector<double> heapAt;  // y: heap bytes at each sample
  cycleAt.reserve(sampleCount + 1);
  heapAt.reserve(sampleCount + 1);

  runSettle();
  cycleAt.push_back(0.0);
  heapAt.push_back(static_cast<double>(current_heap_bytes()));

  size_t completed = 0;
  for (size_t s = 1; s <= sampleCount; ++s)
  {
    const size_t target = iterations * s / sampleCount;  // evenly spaced checkpoints
    for (; completed < target; ++completed)
      cycle();
    runSettle();
    cycleAt.push_back(static_cast<double>(completed));
    heapAt.push_back(static_cast<double>(current_heap_bytes()));
  }

  // Every read 0 means this platform has no heap measurement mechanism: the stability verdict cannot
  // be reached, which is a failure naming what is missing, not a pass.
  if (std::all_of(heapAt.begin(), heapAt.end(), [](double v) { return v == 0.0; }))
  {
    FAIL() << "missing precondition: no heap measurement mechanism on this platform (needs an "
              "ASan build or glibc mallinfo2); ran "
           << iterations << " cycles but cannot assert heap stability.";
  }

  // Least-squares slope (bytes per iteration) of heap vs cycle.
  const size_t n = cycleAt.size();
  double sumX = 0.0, sumY = 0.0, sumXX = 0.0, sumXY = 0.0;
  for (size_t i = 0; i < n; ++i)
  {
    sumX += cycleAt[i];
    sumY += heapAt[i];
    sumXX += cycleAt[i] * cycleAt[i];
    sumXY += cycleAt[i] * heapAt[i];
  }
  const double denom = static_cast<double>(n) * sumXX - sumX * sumX;
  const double slope = denom != 0.0 ? (static_cast<double>(n) * sumXY - sumX * sumY) / denom : 0.0;

  // Projected sustained growth over the full run, from the trend. Clamp at 0: a flat or shrinking
  // heap cannot leak. Gate on this instead of a single noisy endpoint.
  const double projectedGrowth = std::max(0.0, slope) * static_cast<double>(iterations);

  // One concise diagnostic line, always (a leak loop's whole point is this number).
  std::cerr << "[heap] slope=" << slope << " B/iter  projected=" << projectedGrowth
            << " B  tolerance=" << toleranceBytes << " B  (" << n << " samples over " << iterations
            << " cycles, " << (heap_measurement_is_precise() ? "precise/ASan" : "imprecise/glibc") << ")\n";

  // On the imprecise (glibc mallinfo2) path the slope is allocator-fragmentation noise, not a leak -
  // gating on it is what made this test flaky across non-ASan jobs. Run the loop for coverage but do
  // NOT assert the byte tolerance here; the precise byte gate runs under the ASan preset, and any
  // exact instance-count pins the caller adds still assert on every build.
  if (!heap_measurement_is_precise())
    return;

  EXPECT_LE(projectedGrowth, static_cast<double>(toleranceBytes))
    << "Heap shows a sustained positive growth trend across " << iterations << " cycles:\n"
    << "  slope            = " << slope << " bytes/iteration\n"
    << "  projected growth = " << projectedGrowth << " bytes (slope x iterations)\n"
    << "  tolerance        = " << toleranceBytes << " bytes\n"
    << "  first/last heap  = " << heapAt.front() << " / " << heapAt.back() << " bytes\n"
    << "  samples          = " << n;
}

}  // namespace ua::test_helpers
