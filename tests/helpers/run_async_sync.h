// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_HELPERS_RUN_ASYNC_SYNC_H
#define UA_TEST_HELPERS_RUN_ASYNC_SYNC_H

// Test-only helper that synchronously drives an *_async invocation by setting
// a promise from the callback and waiting on its future. Used by tests that
// previously relied on Task<T>::value()-style coroutine sync drivers (now
// removed alongside the various legacy *_coro adapters per the async
// migration).
//
// MUST only be called from a thread that is NOT on the SDK thread pool -
// typically the gtest main thread. Calling .get() from a pool thread would
// deadlock a single-threaded executor and starve a multi-threaded one.
//
// Usage (std::function<void(T)> producers):
//   auto result = ua::test_helpers::run_async_callback_sync<DecodedMessageChunkResult>(
//       [&](auto cb) { policy->decode_message_chunk_async(ctx, std::move(chunk), std::move(cb)); });
//
// Usage (raw std::function<void(T)> producers):
//   auto result = ua::test_helpers::run_async_function_sync<VoidResult>(
//       [&](auto cb) { obj.do_thing_async(std::move(cb)); });

#include <functional>
#include <future>
#include <utility>

namespace ua::test_helpers
{

// For producers that take a `std::function<void(T)>` (the SDK's guaranteed-callback type).
template<typename T, typename F>
T run_async_callback_sync(F&& invoke)
{
  std::promise<T> promise;
  auto future = promise.get_future();
  std::forward<F>(invoke)([&promise](T result) mutable { promise.set_value(std::move(result)); });
  return future.get();
}

// For producers that take a raw `std::function<void(T)>`.
template<typename T, typename F>
T run_async_function_sync(F&& invoke)
{
  std::promise<T> promise;
  auto future = promise.get_future();
  std::forward<F>(invoke)([&promise](T result) mutable { promise.set_value(std::move(result)); });
  return future.get();
}

}  // namespace ua::test_helpers

#endif  // UA_TEST_HELPERS_RUN_ASYNC_SYNC_H
