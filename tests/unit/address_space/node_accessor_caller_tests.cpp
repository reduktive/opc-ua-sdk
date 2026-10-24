// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The caller an accessor's value forms are given reaches the owning namespace's batched members
/// unchanged (COMP-ADDRSP-ACCESSOR-ROUTE-03).

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <span>
#include <utility>
#include <vector>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_default_namespace.h"
#include "ua_namespace.h"
#include "ua_namespace_authorization.h"
#include "ua_namespace_items.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_read_value_id.h"
#include "ua_request_info.h"
#include "ua_server_authentication.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_write_value.h"
#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// The callers the namespace's value members received, in order.
struct CallerLog
{
  std::mutex mutex;
  std::vector<const CallerInfo*> reads;
  std::vector<const CallerInfo*> writes;
};

/// Holds an in-memory namespace, forwards the members to it, and records the caller of each
/// `read_values_async` and `write_async` before answering through the in-memory namespace.
class CallerRecordingNamespace final : public Namespace
{
public:
  using Namespace::find_node;

  CallerRecordingNamespace(std::shared_ptr<default_ns::Namespace> inner, std::shared_ptr<CallerLog> log)
    : mInner(std::move(inner)), mLog(std::move(log))
  {}

  String uri() const override
  {
    return mInner->uri();
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    mInner->find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    return mInner->find_node(nodeId, maxAge);
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mInner->create_nodes_async(request, nodes, std::move(complete));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    mInner->read_references_async(request, queries, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    {
      const std::lock_guard lock(mLog->mutex);
      mLog->reads.push_back(caller);
    }
    mInner->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    {
      const std::lock_guard lock(mLog->mutex);
      mLog->writes.push_back(caller);
    }
    mInner->write_async(request, caller, items, std::move(complete));
  }

private:
  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mInner->attach(context);
  }

  std::shared_ptr<default_ns::Namespace> mInner;
  std::shared_ptr<CallerLog> mLog;
};

/// Starts an operation with a completion and waits up to 5 s for its first answer.
template<typename T, typename Start>
std::optional<T> await_answer(Start&& start)
{
  auto promise = std::make_shared<std::promise<T>>();
  auto answered = std::make_shared<std::atomic<bool>>(false);
  auto future = promise->get_future();
  start(std::function<void(T)>{[promise, answered](T answer)
    {
      if (!answered->exchange(true))
      {
        promise->set_value(std::move(answer));
      }
    }});
  if (future.wait_for(5s) != std::future_status::ready)
  {
    return std::nullopt;
  }
  return future.get();
}

template<typename T>
Status status_of(const std::optional<T>& answer)
{
  return answer.has_value() ? answer->status_code().as_status() : Status::BadTimeout;
}

/// The status an answer carries, as text, for a failure message.
template<typename T>
std::string text_of(const std::optional<T>& answer)
{
  std::ostringstream text;
  if (answer.has_value())
  {
    text << to_string(answer->status_code());
  }
  else
  {
    text << "no answer within 5 s";
  }
  return text.str();
}

}  // namespace

// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-03-THE-VALUE-FORMS-PASS-THE-CALLER-UNCHANGED, scope=function)
TEST(NodeAccessorRoute, TheValueFormsPassTheCallerUnchanged)
{
  boost::asio::thread_pool pool{2};
  {
    auto log = std::make_shared<CallerLog>();
    auto addressSpace = AddressSpace::create("urn:test:node-accessor-caller", pool.get_executor());
    const auto index = addressSpace.add_namespace_sync(std::make_shared<CallerRecordingNamespace>(
      default_ns::Namespace::create("urn:test:accessor-caller-r", pool.get_executor()), log));
    ASSERT_NE(index, 0);
    const NodeId vId{index, "V"};
    ASSERT_TRUE(addressSpace.try_create_node_sync(vId, NodeClass::Variable, {}).is_good());
    auto variable = addressSpace.try_find_sync<VariableAccessor>(vId);
    ASSERT_TRUE(variable.is_good()) << to_string(variable.status_code());
    VariableAccessor v = variable.value();
    {
      const std::lock_guard lock(log->mutex);
      log->reads.clear();
      log->writes.clear();
    }

    CallerInfo caller;
    caller.identity = std::make_shared<const AccessIdentity>(AccessIdentityKey{31},
      std::vector<NodeId>{NodeId{ObjectId::WellKnownRole_Operator}},
      std::make_shared<const UserIdentity>(),
      std::make_shared<const EndpointSecurityContext>(),
      String{"urn:test:accessor-caller-client"});

    ReadValueId read;
    read.node_id() = vId;
    read.attribute_id() = utils::to_underlying(AttributeId::Value);
    WriteValue write;
    write.node_id() = vId;
    write.attribute_id() = utils::to_underlying(AttributeId::Value);
    write.value() = DataValue{Variant{int32_t{3}}};

    const auto readAnswer = await_answer<DataValueResult>(
      [&](auto done) { v.read_value_async(Duration{0}, true, read, &caller, std::move(done)); });
    const auto writeAnswer =
      await_answer<VoidResult>([&](auto done) { v.write_value_async(write, &caller, std::move(done)); });
    const auto internalWrite = await_answer<VoidResult>(
      [&](auto done) { v.write_value_async(DataValue{Variant{int32_t{4}}}, std::move(done)); });

    EXPECT_EQ(status_of(readAnswer), Status::Good) << "answered " << text_of(readAnswer) << ' ';
    EXPECT_EQ(status_of(writeAnswer), Status::Good) << "answered " << text_of(writeAnswer) << ' ';
    EXPECT_EQ(status_of(internalWrite), Status::Good) << "answered " << text_of(internalWrite) << ' ';
    const std::lock_guard lock(log->mutex);
    ASSERT_EQ(log->reads.size(), 1u) << "read_values_async was called " << log->reads.size() << " times";
    EXPECT_EQ(log->reads[0], &caller) << "read_values_async did not receive the caller's address";
    ASSERT_EQ(log->writes.size(), 2u) << "write_async was called " << log->writes.size() << " times";
    EXPECT_EQ(log->writes[0], &caller) << "the first write_async did not receive the caller's address";
    EXPECT_EQ(log->writes[1], nullptr) << "the write without a caller did not pass a null caller";
  }
  ::ua::test_utils::drain_with_timeout(pool);
}
