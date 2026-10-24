// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_LIVENESS_WATCHDOG_H
#define FUZZ_LIVENESS_WATCHDOG_H

#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace fuzz
{

/// Detects *synchronous blocking* on a single-threaded server executor.
///
/// The SDK is callback-canonical: no handler may block the executor thread. A stray `*_sync`
/// call, a `future.get()`, or blocking I/O on the strand stalls a SINGLE-threaded server
/// forever (a multi-threaded server hides it - another thread keeps servicing work). This
/// watchdog runs on its OWN thread, periodically posts a no-op "heartbeat" onto the watched
/// executor, and waits up to `deadline` for it to run. Legitimate handlers complete in
/// microseconds; a synchronous block never completes - so a missed heartbeat means the
/// executor thread is wedged. On a miss it invokes `onStall` exactly once.
///
/// Lifetime: the heartbeat closures hold a shared_ptr to the watchdog's internal state, so an
/// in-flight heartbeat posted just before destruction is safe even after the watchdog is gone.
class LivenessWatchdog
{
public:
  /// @param executor  the (single-threaded) server executor to probe.
  /// @param deadline  max time a heartbeat may take to run before declaring a stall.
  /// @param interval  gap between successful probes.
  /// @param onStall   invoked once, from the watchdog thread, on a missed heartbeat. Typically
  ///                  logs the in-flight fuzz case and aborts (so a gdb-wrapped run dumps the
  ///                  wedged thread's backtrace).
  LivenessWatchdog(boost::asio::any_io_executor executor, std::chrono::milliseconds deadline,
    std::chrono::milliseconds interval, std::function<void()> onStall);
  ~LivenessWatchdog();

  LivenessWatchdog(const LivenessWatchdog&) = delete;
  LivenessWatchdog& operator=(const LivenessWatchdog&) = delete;

private:
  struct State
  {
    std::mutex mutex;
    std::condition_variable cv;
    uint64_t pingSeq{0};
    uint64_t pongSeq{0};
    bool stop{false};
  };

  void loop();

  boost::asio::any_io_executor mExecutor;
  std::chrono::milliseconds mDeadline;
  std::chrono::milliseconds mInterval;
  std::function<void()> mOnStall;
  std::shared_ptr<State> mState;
  std::thread mThread;
};

}  // namespace fuzz

#endif  // !FUZZ_LIVENESS_WATCHDOG_H
