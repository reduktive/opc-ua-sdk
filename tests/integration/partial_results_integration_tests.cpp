// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Partial results before the client's deadline (API review item 10), over the wire.
///
/// A namespace whose reads of one source's References, and whose history delegate, answer only when the test
/// releases them is mounted in a real server; an SDK client drives Browse, BrowseNext and HistoryRead against
/// it over TCP. The server is configured with a partial-result deadline fraction of 0.25, so a request with a
/// 2000 ms timeoutHint is answered at about 500 ms with what it has. The held call is released at about
/// 1000 ms: under the default fraction of 0.8 the same request would be answered at about 1600 ms with the
/// released result, which is what makes the fraction's row in the configuration coverage matrix non-vacuous.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <thread>
#include <vector>

#include "batch_recording_namespace.h"
#include "compliance_helpers.h"
#include "requests.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_default_namespace.h"
#include "ua_history_data.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_referencetype_id.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_method_id.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_session_method_services.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_session_attribute_services.h"
#include "ua_session_view_services.h"
#include "ua_value_source.h"
#include "ua_variant.h"

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// History reads, namespace calls and value reads and writes that answer only when the test releases them.
class GatedDelegates final : public NamespaceHistoryDelegate
{
public:
  ~GatedDelegates() override
  {
    release_held();
  }

  void hold_call(size_t count, std::function<void(BatchResult<std::optional<CallResult>>)> callback)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mCalls.push_back(
      Held<std::function<void(BatchResult<std::optional<CallResult>>)>>{count, std::move(callback)});
  }

  void hold_value_read(std::function<void(DataValueResult)> done)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mValueReads.push_back(std::move(done));
  }

  void hold_value_write(std::function<void(ValueSource::WriteResult)> done)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mValueWrites.push_back(std::move(done));
  }

  /// Answers every held value read, value write and call; their answers arrive after the request was
  /// answered and have nowhere to go.
  void release_held()
  {
    std::vector<std::function<void(DataValueResult)>> reads;
    std::vector<std::function<void(ValueSource::WriteResult)>> writes;
    std::vector<Held<std::function<void(BatchResult<std::optional<CallResult>>)>>> calls;
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      reads = std::move(mValueReads);
      writes = std::move(mValueWrites);
      calls = std::move(mCalls);
    }
    for (auto& read : reads)
    {
      read(DataValue{Variant{int32_t{-1}}});
    }
    for (auto& write : writes)
    {
      write(ValueSource::Written{});
    }
    for (auto& call : calls)
    {
      BatchResult<std::optional<CallResult>> batch;
      for (size_t i = 0; i < call.count; ++i)
      {
        batch.items.emplace_back(CallResult{CallMethodResult{}});
      }
      call.callback(std::move(batch));
    }
  }

  Capabilities capabilities() const noexcept override
  {
    Capabilities capabilities;
    capabilities.readRaw = true;
    return capabilities;
  }

  void read_raw_async(
    const ReadContext&, std::vector<ReadRawItem> items, ReadRawCallback callback) noexcept override
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    mReads.push_back(Held<ReadRawCallback>{items.size(), std::move(callback)});
    mArrived.notify_all();
  }

  bool wait_for_read(std::chrono::milliseconds limit = 3000ms)
  {
    std::unique_lock<std::mutex> lock(mMutex);
    return mArrived.wait_for(lock, limit, [this] { return !mReads.empty(); });
  }

  void release_read(int32_t value)
  {
    auto held = take(mReads);
    BatchResult<ReadRawItemResult> batch;
    for (size_t i = 0; i < held.count; ++i)
    {
      HistoryReadRawSuccess success;
      DataValue dv;
      dv.value() = value;
      dv.source_timestamp() = DateTime::now();
      dv.server_timestamp() = DateTime::now();
      success.values.push_back(std::move(dv));
      batch.items.emplace_back(std::move(success));
    }
    held.callback(std::move(batch));
  }

private:
  template<typename Callback>
  struct Held
  {
    size_t count{0};
    Callback callback;
  };

  template<typename Callback>
  Held<Callback> take(std::vector<Held<Callback>>& queue)
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    auto held = std::move(queue.front());
    queue.erase(queue.begin());
    return held;
  }

  std::mutex mMutex;
  std::condition_variable mArrived;
  std::vector<Held<ReadRawCallback>> mReads;
  std::vector<Held<std::function<void(BatchResult<std::optional<CallResult>>)>>> mCalls;
  std::vector<std::function<void(DataValueResult)>> mValueReads;
  std::vector<std::function<void(ValueSource::WriteResult)>> mValueWrites;
};

/// A namespace whose reads of the References of the Nodes it is told to hold answer only when the test
/// releases them, with gated history reads and namespace calls.
class GatedNamespace final : public ua::test::BatchRecordingNamespace
{
public:
  GatedNamespace(string_view uri, boost::asio::any_io_executor executor, shared_ptr<GatedDelegates> delegates)
    : ua::test::BatchRecordingNamespace(uri, std::move(executor)), mDelegates(std::move(delegates))
  {
    set_history_delegate(mDelegates);
  }

  void call_async(const RequestInfo&, const CallerInfo*, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override
  {
    mDelegates->hold_call(items.size(), std::move(complete));
  }

private:
  shared_ptr<GatedDelegates> mDelegates;
};

/// Releases @p release about @p after the request was sent, from another thread, once the call arrived.
std::thread release_later(std::function<bool()> arrived, std::function<void()> release,
  std::chrono::steady_clock::time_point sent, std::chrono::milliseconds after)
{
  return std::thread{[arrived = std::move(arrived), release = std::move(release), sent, after]
    {
      if (arrived())
      {
        std::this_thread::sleep_until(sent + after);
        release();
      }
    }};
}

class PartialResultsIntegrationBase : public ComplianceWithNodes
{
protected:
  using PartialResultsIntegrationBaseParent = ComplianceWithNodes;

  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    auto addressSpace = mServer.server().address_space();
    mDelegates = std::make_shared<GatedDelegates>();
    mGated = std::make_shared<GatedNamespace>(
      "urn:test:partial-results", mServer.thread_pool().executor(), mDelegates);
    mGatedIndex = addressSpace.add_namespace_sync(mGated);
    mGated->set_namespace_defaults(test_namespace_role_permissions(), std::nullopt);

    mGatedObject = NodeId{mGatedIndex, uint32_t{1}};
    auto object = addressSpace.create_node_sync(mGatedObject, NodeClass::Object);
    object.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});

    mGatedVariable = NodeId{mGatedIndex, uint32_t{2}};
    auto variableNode = addressSpace.create_node_sync(mGatedVariable, NodeClass::Variable);
    variableNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = variableNode.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::HistoryRead});

    mGatedMethod = NodeId{mGatedIndex, uint32_t{3}};
    auto method = addressSpace.create_node_sync(mGatedMethod, NodeClass::Method);
    object.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mGatedMethod);
    auto methodAccessor = method.as<MethodAccessor>();
    ASSERT_TRUE(methodAccessor.has_value());
    methodAccessor->set_executable(true);

    // A source whose one Organizes Reference, to an Object whose BrowseName is "Released", is read only when
    // the test releases the read.
    mGatedSource = NodeId{mGatedIndex, uint32_t{5}};
    auto gatedSource = addressSpace.create_node_sync(mGatedSource, NodeClass::Object);
    gatedSource.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    const NodeId releasedId{mGatedIndex, uint32_t{6}};
    auto released = addressSpace.create_node_sync(releasedId, NodeClass::Object);
    released.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    released.set_browse_name(QualifiedName{0, "Released"});
    gatedSource.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{releasedId}, true);
    released.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{mGatedSource}, false);
    mGated->hold_reference_reads_of({mGatedSource});

    // A Variable whose value reads and writes answer only when released.
    mHeldValue = NodeId{mGatedIndex, uint32_t{4}};
    auto heldNode = addressSpace.create_node_sync(mHeldValue, NodeClass::Variable);
    heldNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto held = heldNode.as<VariableAccessor>();
    ASSERT_TRUE(held.has_value());
    held->set_data_type(NodeId{DataTypeId::Int32});
    held->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    auto* source = (*held)->external_value_source();
    ASSERT_NE(source, nullptr);
    std::weak_ptr<GatedDelegates> delegates = mDelegates;
    ASSERT_TRUE(source
                  ->set_value_source(make_value_source(
                    [delegates](const ValueSource::ReadContext&,
                      const Node&,
                      const ReadValueId&,
                      std::function<void(DataValueResult)>
                        done)
                    {
                      if (auto gate = delegates.lock())
                      {
                        gate->hold_value_read(std::move(done));
                      }
                    },
                    [delegates](const ValueSource::WriteContext&,
                      const Node&,
                      const WriteValue&,
                      std::function<void(ValueSource::WriteResult)>
                        done)
                    {
                      if (auto gate = delegates.lock())
                      {
                        gate->hold_value_write(std::move(done));
                      }
                    }))
                  .is_good());
  }

  void TearDown() override
  {
    if (mGated)
    {
      mGated->hold_reference_reads_of({});
      mGated->release_held_reference_reads();
    }
    if (mDelegates)
    {
      mDelegates->release_held();
    }
    PartialResultsIntegrationBaseParent::TearDown();
  }

  /// A Browse of the gated source's Organizes References.
  BrowseRequest browse_gated(uint32_t timeoutHint)
  {
    auto request = BrowseRequestBuilder()
                     .browse(mGatedSource)
                     .reference_type(NodeId{ReferenceTypeId::Organizes})
                     .include_subtypes(true)
                     .build();
    request.request_header().timeout_hint() = timeoutHint;
    return request;
  }

  bool wait_for_browse()
  {
    return mGated->wait_for_held_reference_reads(1, 3000ms);
  }

  void release_browse()
  {
    mGated->release_held_reference_reads();
  }

  shared_ptr<GatedDelegates> mDelegates;
  shared_ptr<GatedNamespace> mGated;
  uint16_t mGatedIndex{0};
  NodeId mGatedObject;
  NodeId mGatedVariable;
  NodeId mGatedMethod;
  NodeId mHeldValue;
  NodeId mGatedSource;
};

class PartialResultsIntegration : public PartialResultsIntegrationBase
{
protected:
  void configure_server_config(ua::server::ServerConfig& serverCfg) override
  {
    serverCfg.partialResultDeadlineFraction = 0.25;  // default 0.8
  }
};

/// The default fraction, for the control.
class PartialResultsIntegrationDefaultFraction : public PartialResultsIntegrationBase
{};

}  // namespace

// Row: ServerConfig::partialResultDeadlineFraction.
// A Browse of a namespace whose reference read is slower than the deadline is answered before the client's
// timeout, Good with no references and a continuation point; the BrowseNext that continues it returns the
// namespace's reference.
// @relation(AC-SVR-PARTIAL-RESULTS-001-WIRE-PAUSE-AND-RESUME, scope=function)
TEST_F(PartialResultsIntegration, ABrowseOfASlowNamespaceIsAnsweredBeforeTheClientTimesOut)
{
  const auto sent = std::chrono::steady_clock::now();
  auto releaser =
    release_later([this] { return wait_for_browse(); }, [this] { release_browse(); }, sent, 1000ms);
  auto response = mSession->view().browse_sync(browse_gated(2000));
  const auto elapsed = std::chrono::steady_clock::now() - sent;
  releaser.join();

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code().as_status(), Status::Good);
  EXPECT_TRUE(response.results()[0].references().empty());
  ASSERT_FALSE(response.results()[0].continuation_point().empty())
    << "the slow operation must be handed to a continuation point at the deadline";
  EXPECT_LT(elapsed, 1000ms) << "answered at 25 % of the 2000 ms hint, before the slow call finished";

  auto next = mSession->view().browse_next_sync(browse_next(response.results()[0].continuation_point()));
  ASSERT_EQ(next.results().size(), 1u);
  EXPECT_EQ(next.results()[0].status_code().as_status(), Status::Good);
  ASSERT_EQ(next.results()[0].references().size(), 1u);
  EXPECT_EQ(next.results()[0].references()[0].browse_name(), (QualifiedName{0, "Released"}));
}

// Control for the row above: under the default fraction (0.8) the same request is answered at about
// 1600 ms, after the slow read finished at about 1000 ms, so the reference is in the first response.
// @relation(AC-SVR-PARTIAL-RESULTS-001-WIRE-PAUSE-AND-RESUME, scope=function)
TEST_F(PartialResultsIntegrationDefaultFraction, ABrowseFinishedBeforeTheDefaultDeadlineIsAnsweredWhole)
{
  const auto sent = std::chrono::steady_clock::now();
  auto releaser =
    release_later([this] { return wait_for_browse(); }, [this] { release_browse(); }, sent, 1000ms);
  auto response = mSession->view().browse_sync(browse_gated(2000));
  releaser.join();

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code().as_status(), Status::Good);
  EXPECT_EQ(response.results()[0].references().size(), 1u);
  EXPECT_TRUE(response.results()[0].continuation_point().empty());
}

// A HistoryRead of a history source slower than the deadline is answered before the client's timeout with
// zero values and a continuation point; continuing it returns the values the slow read produced.
// @relation(AC-SVR-PARTIAL-RESULTS-002-WIRE-PAUSE-AND-RESUME, scope=function)
TEST_F(PartialResultsIntegration, AHistoryReadOfASlowSourceIsAnsweredBeforeTheClientTimesOut)
{
  auto request =
    HistoryReadRawBuilder(DateTime{DateTime::min()}, DateTime::now()).read(mGatedVariable).build();
  request.request_header().timeout_hint() = 2000;

  const auto sent = std::chrono::steady_clock::now();
  auto releaser = release_later(
    [this] { return mDelegates->wait_for_read(); }, [this] { mDelegates->release_read(42); }, sent, 1000ms);
  auto response = mSession->attributes().history_read_sync(std::move(request));
  const auto elapsed = std::chrono::steady_clock::now() - sent;
  releaser.join();

  ASSERT_EQ(response.results().size(), 1u);
  EXPECT_EQ(response.results()[0].status_code().as_status(), Status::Good);
  const auto point = response.results()[0].continuation_point();
  ASSERT_FALSE(point.empty()) << "the slow read must be handed to a continuation point at the deadline";
  EXPECT_LT(elapsed, 1000ms);

  auto next = mSession->attributes().history_read_sync(
    HistoryReadRawBuilder(DateTime{DateTime::min()}, DateTime::now()).read(mGatedVariable, point).build());
  ASSERT_EQ(next.results().size(), 1u);
  EXPECT_EQ(next.results()[0].status_code().as_status(), Status::Good);
  auto* values = dynamic_cast<HistoryData*>(next.results()[0].history_data().get());
  ASSERT_NE(values, nullptr);
  ASSERT_EQ(values->data_values().size(), 1u);
  EXPECT_EQ(values->data_values()[0].value().as<int32_t>(), 42);
}

// The SDK client waits past the timeoutHint it sends (CL-SESS-030), so it receives the Read the server
// answers at the hint: the finished item carries its value and the unfinished one Bad_Timeout. With a
// client deadline equal to the hint, the client fails the call locally before the answer arrives.
// @relation(AC-SVR-PARTIAL-RESULTS-003-WIRE-PER-ITEM, scope=function)
// @relation(AC-CL-SESS-030-WIRE-ANSWER-AT-THE-HINT, scope=function)
TEST_F(PartialResultsIntegration, AReadOfASlowValueIsAnsweredPerItemAtTheTimeoutHint)
{
  ReadRequest request = ReadRequestBuilder()
                          .read(mWritableVariableId)
                          .attribute(AttributeId::Value)
                          .read(mHeldValue)
                          .attribute(AttributeId::Value);
  request.request_header().timeout_hint() = 1000;

  const auto sent = std::chrono::steady_clock::now();
  auto response = mSession->attributes().try_read_sync(std::move(request));
  const auto elapsed = std::chrono::steady_clock::now() - sent;

  ASSERT_TRUE(response.is_good()) << "the answer sent at the hint must reach the client: "
                                  << to_string(response.status_code());
  ASSERT_EQ(response.value().results().size(), 2u);
  ASSERT_TRUE(response.value().results()[0].status().value_or(StatusCode{Status::Good}).is_good())
    << to_string(response.value().results()[0].status().value_or(StatusCode{Status::Good}));
  EXPECT_EQ(response.value().results()[0].value().as<int32_t>(), 42);
  EXPECT_EQ(response.value().results()[1].status().value_or(StatusCode{Status::Good}).as_status(),
    Status::BadTimeout);
  EXPECT_GE(elapsed, 950ms) << "Read runs to the full timeoutHint";
}

// Write: the finished item is Good and the unfinished one Bad_Timeout, its outcome unknown.
// @relation(AC-SVR-PARTIAL-RESULTS-003-WIRE-PER-ITEM, scope=function)
TEST_F(PartialResultsIntegration, AWriteOfASlowValueIsAnsweredPerItemAtTheTimeoutHint)
{
  WriteRequest request = WriteRequestBuilder()
                           .write(mWritableVariableId, Variant{int32_t{43}})
                           .write(mHeldValue, Variant{int32_t{44}});
  request.request_header().timeout_hint() = 1000;

  auto response = mSession->attributes().try_write_sync(std::move(request));

  ASSERT_TRUE(response.is_good()) << to_string(response.status_code());
  ASSERT_EQ(response.value().results().size(), 2u);
  EXPECT_TRUE(response.value().results()[0].is_good());
  EXPECT_EQ(response.value().results()[1].as_status(), Status::BadTimeout);
}

// Call: a call that finished carries its own result and the unfinished one Bad_Timeout. The finished
// call is Server.GetMonitoredItems for a Subscription that does not exist.
// @relation(AC-SVR-PARTIAL-RESULTS-003-WIRE-PER-ITEM, scope=function)
TEST_F(PartialResultsIntegration, ACallOfASlowMethodIsAnsweredPerItemAtTheTimeoutHint)
{
  CallRequest request = CallRequestBuilder()
                          .call(NodeId{ObjectId::Server}, NodeId{MethodId::Server_GetMonitoredItems})
                          .argument(Variant{uint32_t{987654}})
                          .call(mGatedObject, mGatedMethod);
  request.request_header().timeout_hint() = 1000;

  auto response = mSession->methods().try_call_sync(std::move(request));

  ASSERT_TRUE(response.is_good()) << to_string(response.status_code());
  ASSERT_EQ(response.value().results().size(), 2u);
  EXPECT_EQ(response.value().results()[0].status_code().as_status(), Status::BadSubscriptionIdInvalid);
  EXPECT_EQ(response.value().results()[1].status_code().as_status(), Status::BadTimeout);
}
