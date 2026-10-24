// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// What a bucket tick reports when it cannot keep up.
///
/// D16 records that a bucket whose work exceeded its interval fell behind and said nothing about it. A
/// tick now counts what it loses when it cannot fit.
///
/// Read delays are used rather than item counts alone, so the serial cost of a tick is arithmetic rather
/// than a property of the machine. That is what lets these assert a bound without becoming a benchmark
/// that drifts with build type and load.

#include <gtest/gtest.h>

#include "node_value_reader.h"
#include "test_utilities.h"

#include "ua_data_value.h"
#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_default_variable_node.h"
#include "ua_sampling_engine.h"
#include "ua_sinks.h"
#include "ua_variant.h"
#include "ua_write_value.h"
#include "ua_value_source.h"

#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// Counts what arrives and otherwise does as little as possible, so the figure attributes cost to the
/// engine rather than to the sink.
class CountingSink final : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    mPushed.fetch_add(samples.size(), std::memory_order_relaxed);
  }

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}

  size_t pushed() const
  {
    return mPushed.load(std::memory_order_relaxed);
  }

private:
  std::atomic<size_t> mPushed{0};
};

/// Answers every read from a detached thread after a fixed delay, which is what a device-backed
/// namespace does and what makes the serial cost of a tick predictable. A new value every time, so
/// every read is a change and the tick does its full work.
///
/// Keeps count of the threads still delivering, because each one posts its answer onto the engine's
/// strand: a thread still sleeping when the test ends would post onto an executor that is already gone
/// and corrupt whatever the next test allocates there. Declare it right after the thread pool, so it is
/// destroyed just before the pool even when an assertion returns early; @ref wait_idle stops new
/// threads (later reads are answered inline) and waits for the ones in flight.
class DelayedReads
{
public:
  explicit DelayedReads(std::chrono::milliseconds delay) : mDelay(delay)
  {}

  DelayedReads(const DelayedReads&) = delete;
  DelayedReads& operator=(const DelayedReads&) = delete;

  ~DelayedReads()
  {
    wait_idle();
  }

  auto handler() const
  {
    return [state = mState, delay = mDelay](const ValueSource::ReadContext& /*context*/,
             const Node&,
             const ReadValueId&,
             std::function<void(DataValueResult)>
               complete)
    {
      // Counted before the check, so a wait that has already seen zero also sees the stop.
      state->inFlight.fetch_add(1);
      if (state->stopped.load())
      {
        state->inFlight.fetch_sub(1);
        complete(next_value(*state));
        return;
      }
      std::thread{[state, complete = std::move(complete), delay]() mutable
        {
          std::this_thread::sleep_for(delay);
          {
            // Released before the count drops: the completion holds the engine's strand, and nothing
            // of it may outlive the wait.
            auto done = std::move(complete);
            done(next_value(*state));
          }
          state->inFlight.fetch_sub(1);
        }}
        .detach();
    };
  }

  void wait_idle()
  {
    mState->stopped.store(true);
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (mState->inFlight.load() != 0 && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(mState->inFlight.load(), 0) << "a delayed read never finished delivering";
  }

private:
  struct State
  {
    std::atomic<int32_t> counter{0};
    std::atomic<int32_t> inFlight{0};
    std::atomic<bool> stopped{false};
  };

  static DataValue next_value(State& state)
  {
    DataValue value;
    value.value() = Variant{state.counter.fetch_add(1)};
    value.source_timestamp() = DateTime::now();
    return value;
  }

  std::shared_ptr<State> mState{std::make_shared<State>()};
  std::chrono::milliseconds mDelay;
};

}  // namespace

// A bucket that cannot fit its period says so, in figures a caller can read.
//
// The reader reads the items one after another, so at 5 ms a read this is 320 ms of work in a 50 ms
// period, whatever the machine. Before, the engine accepted that silently -
// the client asked for 50 ms, was told it was granted, and was served at a sixth of the rate with
// nothing in the protocol exchange revealing it. These counters are the remedy D16 asks for, and this
// test is what stops them quietly reading zero.
TEST(SamplingEngineCost, OverrunAndSkippedPeriodsAreCounted)
{
  constexpr size_t items = 64;
  constexpr Duration interval = 50;
  constexpr auto readDelay = 5ms;

  boost::asio::thread_pool pool{4};
  DelayedReads reads{readDelay};
  auto addressSpace = AddressSpace::create("urn:test:sampling-overrun-host", pool.get_executor());
  auto nameSpace = default_ns::Namespace::create("uri://sampling-overrun", pool.get_executor());
  const auto registered = addressSpace.try_add_namespace_sync(nameSpace);
  ASSERT_TRUE(registered.is_good()) << to_string(registered.status_code());

  auto engine = std::make_shared<default_ns::SamplingEngine>(
    pool.get_executor(), test_utils::node_value_reader(pool.get_executor()));
  auto sink = std::make_shared<CountingSink>();

  std::vector<std::shared_ptr<default_ns::VariableNode>> nodes;
  nodes.reserve(items);
  for (size_t index = 0; index < items; ++index)
  {
    const NodeId nodeId{registered.value(), static_cast<uint32_t>(4000 + index)};
    auto node = nameSpace->create_node<default_ns::VariableNode>(nodeId);
    node->set_value_source(make_value_source(reads.handler()));

    default_ns::SamplingEngine::PolledRegistration registration;
    registration.node = node;
    registration.nodeId = nodeId;
    registration.attributeId = AttributeId::Value;
    registration.monitoredItemId = static_cast<IntegerId>(index + 1);
    registration.requestedInterval = interval;
    registration.sink = sink;
    ASSERT_NE(engine->add_polled(registration).handle, 0u) << index;
    nodes.push_back(std::move(node));
  }

  const auto findBucket = [&engine]() -> std::optional<default_ns::SamplingEngine::BucketMetrics>
  {
    for (const auto& entry : engine->metrics())
    {
      if (entry.interval == interval)
      {
        return entry;
      }
    }
    return std::nullopt;
  };

  const auto deadline = std::chrono::steady_clock::now() + 20s;
  while (std::chrono::steady_clock::now() < deadline)
  {
    const auto current = findBucket();
    if (current && current->ticksCompleted >= 2 && current->periodsSkipped > 0)
    {
      break;
    }
    std::this_thread::sleep_for(20ms);
  }

  const auto bucket = findBucket();
  ASSERT_TRUE(bucket.has_value());
  ASSERT_GE(bucket->ticksCompleted, 1u);

  std::fprintf(stderr,
    "\n[OVERRUN] %zu items, %.0f ms read each, %.0f ms interval\n"
    "[OVERRUN]   last tick        %.1f ms\n"
    "[OVERRUN]   ticks over       %llu of %llu completed\n"
    "[OVERRUN]   periods skipped  %llu\n\n",
    bucket->items,
    std::chrono::duration<double, std::milli>(readDelay).count(),
    bucket->interval,
    bucket->lastTickMilliseconds,
    static_cast<unsigned long long>(bucket->ticksOverInterval),
    static_cast<unsigned long long>(bucket->ticksCompleted),
    static_cast<unsigned long long>(bucket->periodsSkipped));

  EXPECT_GT(bucket->lastTickMilliseconds, bucket->interval)
    << "the tick was expected to overrun its period, so the premise of the test is wrong";
  EXPECT_GT(bucket->ticksOverInterval, 0u) << "a tick ran past its interval and nothing recorded it";
  EXPECT_GT(bucket->periodsSkipped, 0u)
    << "periods were lost to the overrun and nothing recorded them - the silent shortfall D16 describes";

  sink.reset();
  engine->shutdown();
  reads.wait_idle();
  engine.reset();
  nodes.clear();
  nameSpace.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}
