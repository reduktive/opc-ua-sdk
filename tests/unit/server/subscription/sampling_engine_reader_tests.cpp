// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The sampling engine reads a tick's polled Values through the reader its owner gives it
// (COMP-SVR-NAMESPACE-CALLS-14 rules 1 and 4): a tick whose reader answers that the registered namespace is
// gone pushes nothing, and the bucket's next tick runs; an item the reader's answer leaves out is failed, not
// given a value nothing produced.

#include <gtest/gtest.h>

#include "ua_sampling_engine.h"

#include "ua_data_value.h"
#include "ua_default_variable_node.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_node.h"
#include "ua_request_info.h"
#include "ua_sinks.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "test_utilities.h"

using namespace ua;
using namespace std::chrono_literals;
using Engine = default_ns::SamplingEngine;

namespace
{

/// A sink whose `caller()` answers the CallerInfo it was given (none by default), and that records each
/// sample and notice it is given, in order.
class RecordingSink final : public SampleSink
{
public:
  explicit RecordingSink(std::shared_ptr<const CallerInfo> caller = nullptr) : mCaller{std::move(caller)}
  {}

  std::shared_ptr<const CallerInfo> caller() const override
  {
    return mCaller;
  }

  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    {
      const std::lock_guard lock{mMutex};
      for (auto& sample : samples)
      {
        mSamples.push_back(std::move(sample.second));
      }
    }
    mArrived.notify_all();
  }

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override
  {
    (void)monitoredItemId;
    {
      const std::lock_guard lock{mMutex};
      mNotices.push_back(reason);
    }
    mArrived.notify_all();
  }

  void detach() override
  {}

  bool wait_for_samples(std::size_t count, std::chrono::milliseconds limit) const
  {
    std::unique_lock lock{mMutex};
    return mArrived.wait_for(lock, limit, [&] { return mSamples.size() >= count; });
  }

  std::vector<DataValue> samples() const
  {
    const std::lock_guard lock{mMutex};
    return mSamples;
  }

  /// Samples and notices received.
  std::size_t received() const
  {
    const std::lock_guard lock{mMutex};
    return mSamples.size() + mNotices.size();
  }

private:
  std::shared_ptr<const CallerInfo> mCaller;
  mutable std::mutex mMutex;
  mutable std::condition_variable mArrived;
  std::vector<DataValue> mSamples;
  std::vector<StatusCode> mNotices;
};

/// The reader's calls: how many were made, and what each sink had received when each was entered.
class ReaderCalls
{
public:
  /// Records a call entered while the two sinks had received @p sampled and @p reported.
  /// @return The call's number, from 1.
  std::size_t enter(std::size_t sampled, std::size_t reported)
  {
    std::size_t number = 0;
    {
      const std::lock_guard lock{mMutex};
      mReceivedAtEntry.emplace_back(sampled, reported);
      number = mReceivedAtEntry.size();
    }
    mEntered.notify_all();
    return number;
  }

  bool wait_for_calls(std::size_t count, std::chrono::milliseconds limit) const
  {
    std::unique_lock lock{mMutex};
    return mEntered.wait_for(lock, limit, [&] { return mReceivedAtEntry.size() >= count; });
  }

  /// What the sampled and the reported sink had received when call @p number was entered.
  std::pair<std::size_t, std::size_t> received_at(std::size_t number) const
  {
    const std::lock_guard lock{mMutex};
    return mReceivedAtEntry.at(number - 1);
  }

private:
  mutable std::mutex mMutex;
  mutable std::condition_variable mEntered;
  std::vector<std::pair<std::size_t, std::size_t>> mReceivedAtEntry;
};

/// An in-memory Variable holding @p value.
std::shared_ptr<default_ns::VariableNode> variable(const NodeId& nodeId, Variant value)
{
  auto node = default_ns::VariableNode::create(nodeId);
  WriteValue write;
  write.node_id() = nodeId;
  write.attribute_id() = utils::to_underlying(AttributeId::Value);
  write.value() = DataValue{std::move(value)};
  std::optional<VoidResult> written;
  node->write_value_async(write, nullptr, [&written](VoidResult result) { written = std::move(result); });
  EXPECT_TRUE(written.has_value() && written->is_good()) << "the Value of " << to_string(nodeId);
  return node;
}

/// Whether @p detail carries @p key with @p value.
bool has_context(const ErrorDetail& detail, const ContextKey& key, std::string_view value)
{
  return std::any_of(detail.context.begin(),
    detail.context.end(),
    [&key, value](const NamedValue& entry) { return entry.key == key.value() && entry.value == value; });
}

/// A polled registration at 100 ms on @p node's Value, delivered to @p sink as @p monitoredItemId.
Engine::PolledRegistration polled(const std::shared_ptr<default_ns::VariableNode>& node,
  IntegerId monitoredItemId, std::shared_ptr<SampleSink> sink)
{
  Engine::PolledRegistration registration;
  registration.node = node;
  registration.nodeId = node->node_id();
  registration.attributeId = AttributeId::Value;
  registration.monitoredItemId = monitoredItemId;
  registration.requestedInterval = 100;
  registration.sink = std::move(sink);
  return registration;
}

/// Reads each item from its Node, as a namespace that is registered would.
std::vector<DataValueResult> read_items(const std::vector<Engine::ValueRead>& items)
{
  std::vector<DataValueResult> answers;
  answers.reserve(items.size());
  for (const auto& item : items)
  {
    std::optional<DataValueResult> answer;
    if (const auto* node = dynamic_cast<const default_ns::BaseNode*>(item.node.get()))
    {
      node->read_value(
        0, true, item.value, nullptr, [&answer](DataValueResult result) { answer = std::move(result); });
    }
    answers.push_back(answer ? std::move(*answer) : DataValueResult{StatusCode{Status::BadInternalError}});
  }
  return answers;
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-14-A-TICK-WHOSE-NAMESPACE-IS-GONE-PUSHES-NOTHING, scope=function)
TEST(SamplingEngineReader, ATickWhoseNamespaceIsGonePushesNothing)
{
  boost::asio::thread_pool pool{2};
  {
    const auto sampledSink = std::make_shared<RecordingSink>();
    const auto reportedSink = std::make_shared<RecordingSink>();
    const auto calls = std::make_shared<ReaderCalls>();

    // The first call answers that the registered namespace is gone; every later one reads the items.
    Engine::ValueReader reader = [calls, sampledSink, reportedSink](std::shared_ptr<const CallerInfo> caller,
                                   std::vector<Engine::ValueRead>
                                     items,
                                   std::function<void(std::optional<std::vector<DataValueResult>>)>
                                     complete)
    {
      (void)caller;
      if (calls->enter(sampledSink->received(), reportedSink->received()) == 1)
      {
        complete(std::nullopt);
        return;
      }
      complete(read_items(items));
    };
    const auto engine = std::make_shared<Engine>(pool.get_executor(), std::move(reader));

    const NodeId sampledId{1, uint32_t{1000}};
    const NodeId reportedId{1, uint32_t{1001}};
    const auto sampledNode = variable(sampledId, Variant{int32_t{42}});
    const auto reportedNode = variable(reportedId, Variant{int32_t{0}});

    Engine::PolledRegistration sampled;
    sampled.node = sampledNode;
    sampled.nodeId = sampledId;
    sampled.attributeId = AttributeId::Value;
    sampled.monitoredItemId = 1;
    sampled.requestedInterval = 100;
    sampled.sink = sampledSink;
    ASSERT_NE(engine->add_polled(std::move(sampled)).handle, 0u);

    Engine::ExceptionRegistration reported;
    reported.node = reportedNode;
    reported.nodeId = reportedId;
    reported.attributeId = AttributeId::Value;
    reported.monitoredItemId = 2;
    reported.requestedInterval = 100;
    reported.queueSize = 1;
    reported.sink = reportedSink;
    ASSERT_NE(engine->add_exception_latest(std::move(reported)).handle, 0u);
    engine->attribute_changed(reportedId, AttributeId::Value, DataValue{Variant{int32_t{7}}});

    // The second call is the bucket's next tick; what the sinks held when it was entered is what the first
    // tick pushed.
    EXPECT_TRUE(calls->wait_for_calls(2, 3s)) << "the bucket's next tick did not read";
    if (calls->wait_for_calls(2, 0ms))
    {
      const auto [sampledReceived, reportedReceived] = calls->received_at(2);
      EXPECT_EQ(sampledReceived, 0u) << "the tick that found the namespace gone pushed to the Sampled item";
      EXPECT_EQ(reportedReceived, 0u) << "the tick that found the namespace gone pushed to the Reported item";
    }
    ASSERT_TRUE(sampledSink->wait_for_samples(1, 3s)) << "the Sampled item received nothing";
    EXPECT_TRUE(sampledSink->samples().front().value() == Variant{int32_t{42}})
      << "the Sampled item received " << to_string(sampledSink->samples().front().value());

    engine->shutdown();
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-14-A-READER-ANSWER-OF-THE-WRONG-SIZE-FAILS-THE-ITEMS-IT-LEFT-UNANSWERED, scope=function)
TEST(SamplingEngineReader, AnAnswerOfTheWrongSizeFailsTheItemsItLeftUnanswered)
{
  boost::asio::thread_pool pool{2};
  {
    auto caller = std::make_shared<CallerInfo>();
    caller->sessionId = NodeId{1, uint32_t{101}};
    const auto firstSink = std::make_shared<RecordingSink>(caller);
    const auto secondSink = std::make_shared<RecordingSink>(caller);

    // The Nodes each item of the reader's first call named, in order.
    struct FirstCall
    {
      std::mutex mutex;
      std::condition_variable entered;
      std::optional<std::vector<const Node*>> items;
    };

    const auto firstCall = std::make_shared<FirstCall>();

    // Every call is answered with one Good value, however many items it names.
    Engine::ValueReader reader = [firstCall](std::shared_ptr<const CallerInfo> callerOfCall,
                                   std::vector<Engine::ValueRead>
                                     items,
                                   std::function<void(std::optional<std::vector<DataValueResult>>)>
                                     complete)
    {
      (void)callerOfCall;
      {
        const std::lock_guard lock{firstCall->mutex};
        if (!firstCall->items)
        {
          std::vector<const Node*> nodes;
          for (const auto& item : items)
          {
            nodes.push_back(item.node.get());
          }
          firstCall->items = std::move(nodes);
        }
      }
      firstCall->entered.notify_all();
      complete(std::vector<DataValueResult>{DataValueResult{DataValue{Variant{int32_t{5}}}}});
    };
    const auto engine = std::make_shared<Engine>(pool.get_executor(), std::move(reader));

    const std::shared_ptr<default_ns::VariableNode> firstNode =
      variable(NodeId{1, uint32_t{2000}}, Variant{int32_t{1}});
    const std::shared_ptr<default_ns::VariableNode> secondNode =
      variable(NodeId{1, uint32_t{2001}}, Variant{int32_t{2}});
    ASSERT_NE(engine->add_polled(polled(firstNode, 1, firstSink)).handle, 0u);
    ASSERT_NE(engine->add_polled(polled(secondNode, 2, secondSink)).handle, 0u);

    std::vector<const Node*> named;
    {
      std::unique_lock lock{firstCall->mutex};
      ASSERT_TRUE(firstCall->entered.wait_for(lock, 3s, [&] { return firstCall->items.has_value(); }))
        << "the tick did not call the reader";
      named = *firstCall->items;
    }
    ASSERT_EQ(named.size(), 2u) << "the tick's one call for its one caller did not name both items";
    ASSERT_TRUE(firstSink->wait_for_samples(1, 3s)) << "the first registration received nothing";
    ASSERT_TRUE(secondSink->wait_for_samples(1, 3s)) << "the second registration received nothing";

    // The item the reader answered is the one its call named first.
    const bool firstAnswered = named[0] == firstNode.get();
    const auto answered = (firstAnswered ? firstSink : secondSink)->samples().front();
    const auto unanswered = (firstAnswered ? secondSink : firstSink)->samples().front();

    EXPECT_TRUE(answered.value() == Variant{int32_t{5}})
      << "the answered item received " << to_string(answered.value());
    EXPECT_TRUE(answered.status().value_or(StatusCode{Status::Good}) == StatusCode{Status::Good})
      << "the answered item received " << to_string(answered.status().value_or(StatusCode{Status::Good}));

    const StatusCode failure = unanswered.status().value_or(StatusCode{Status::Good});
    EXPECT_TRUE(failure == StatusCode{Status::BadInternalError})
      << "the unanswered item received " << to_string(failure) << " " << to_string(unanswered.value());
    const auto detail = failure.shared_detail();
    ASSERT_NE(detail, nullptr) << "the unanswered item's status carries no ErrorDetail";
    EXPECT_EQ(detail->code, "ValueReaderItemCountMismatch");
    EXPECT_TRUE(has_context(*detail, ContextKeys::sizeExpected, "2")) << "size expected is not 2";
    EXPECT_TRUE(has_context(*detail, ContextKeys::sizeActual, "1")) << "size actual is not 1";

    engine->shutdown();
  }
  ::ua::test_utils::drain_with_timeout(pool);
}
