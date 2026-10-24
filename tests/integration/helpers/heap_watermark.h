// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_INTEGRATION_HELPERS_HEAP_WATERMARK_H
#define UA_INTEGRATION_HELPERS_HEAP_WATERMARK_H

#include <cstddef>
#include <functional>

namespace ua::test_helpers
{

// ---------------------------------------------------------------------------
// current_heap_bytes - best-effort live-allocation watermark.
//
// Returns the number of bytes currently allocated on the heap, as a process-
// wide measurement, using the most precise mechanism the platform provides:
//
//   - Under AddressSanitizer (the `gcc-asan` preset, the primary path here):
//     `__sanitizer_get_current_allocated_bytes()` - counts *live* (not freed)
//     allocations exactly, so it is the lowest-noise signal available. A real
//     per-iteration leak shows up as a monotone climb; transient allocator
//     fragmentation does not.
//
//   - Else on glibc: `malloc_trim(0)` to release free top-of-heap pages, then
//     `mallinfo2().uordblks` (total bytes in in-use chunks).
//
//   - On platforms with neither (32-bit musl, Windows): returns 0, which the
//     assertion helper treats as "measurement unsupported" and FAILS, naming the
//     missing mechanism. LeakSanitizer at process exit still catches definitely-lost
//     blocks on the supported platforms.
//
// The return value is only meaningful as a *delta* between two calls on the
// same process; its absolute magnitude is implementation-defined.
// ---------------------------------------------------------------------------
size_t current_heap_bytes();

// ---------------------------------------------------------------------------
// expect_stable_heap - run a create/destroy cycle N times and assert the live
// heap watermark does not grow beyond a tolerance.
//
// Sequence:
//   1. ADAPTIVE warm-up: run cycles in batches of `warmup` until the live heap stops
//      growing (a batch's per-cycle growth stays within tolerance/iterations for two
//      consecutive batches), capped so a genuine unbounded leak still terminates warm-up.
//      The SDK has slowly-warming BOUNDED caches (per-thread buffer pools, interned ids)
//      that settle only after many hundreds of cycles; a small fixed warm-up left that
//      warming in the measured window and mis-read it as a leak.
//   2. run `iterations` cycles, sampling the (settled) heap at ~12 evenly-spaced checkpoints.
//   3. fit a least-squares line to (cycle, heap) and take the SLOPE - the sustained per-iteration
//      trend. Gate on the projected growth (slope x iterations) against `toleranceBytes`.
//
// Why a regression slope and not a single baseline-vs-after pair: one before/after read is too
// noisy - a settled bounded cache, a one-off allocator-arena jump, or a single mistimed sample can
// push the endpoint past an absolute tolerance while the heap is flat on average (this was the
// source of flaky failures). The slope averages the trend over the whole run: a real leak shows a
// constant positive slope; transients and fragmentation do not.
//
// The byte gate is asserted ONLY when measurement is PRECISE (ASan exact live-allocation count). On
// the glibc mallinfo2 path the loop still runs (crash/hang coverage, and any exact instance-count
// pins the caller asserts) but the byte tolerance is NOT asserted - arena/fragmentation noise there
// is load-dependent and swamps a small leak (see heap_measurement_is_precise). Run these under the
// ASan preset for the real gate. If `current_heap_bytes()` returns 0 (unsupported), the helper fails
// the test, naming the missing measurement mechanism.
//
// `settle` defaults to a no-op. Pass a brief drain (e.g. a short sleep that lets the client/server
// pools process teardown posts) when the cycle leaves async teardown in flight - it is run before
// every sample so an in-flight-teardown offset does not tilt the slope.
// ---------------------------------------------------------------------------
void expect_stable_heap(const std::function<void()>& cycle, size_t iterations, size_t warmup,
  size_t toleranceBytes, std::function<void()> settle = {});

// True only when current_heap_bytes() is a precise live-allocation count (ASan). On the glibc
// mallinfo2 path it returns false: that measurement is too noisy (arena/fragmentation) to gate a
// tight per-iteration byte tolerance on. expect_stable_heap asserts the byte gate only when this is
// true; callers may also use it to add precise-only assertions of their own.
bool heap_measurement_is_precise();

}  // namespace ua::test_helpers

#endif  // UA_INTEGRATION_HELPERS_HEAP_WATERMARK_H
