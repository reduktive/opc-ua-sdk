// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Status routing on the client: a server's answer that is not plain Good reaches the application as the
// server sent it.
//
// Each test scripts one answer over the FakeSessionOps tier-0 interface and drives the public handle that
// returns it (Connection, TypedAccess, BrowseCursor, Subscriptions, Subscription), asserting the exact code
// the application receives:
//   - a typed read answers one code, the combined status of the read's result and the DataValue's status,
//     holding the decoded value for a Good subcode or an Uncertain code (and no value for an Uncertain
//     DataValue without one); its throwing form throws for an Uncertain answer;
//   - a Write's, a Call's, a TranslateBrowsePaths' and a Browse page's Good subcode or Uncertain code is the
//     status of the result that holds the answer;
//   - the ServiceResult of a chunked request is every chunk's ServiceResult combined;
//   - a Subscription's and a MonitoredItem's creation code reaches the handle's result;
//   - a StatusChangeNotification of Good_SubscriptionTransferred ends the Subscription and reaches the
//     SubscriptionObserver with that code; another code reaches the ConnectionObserver as an advisory;
//   - a ServiceFault with an Uncertain code (a result with that code and no value) completes every facade's
//     callback with that code.

#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"

#include "ua_attribute_id.h"
#include "ua_browse_cursor.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_call_method_result.h"
#include "ua_call_response.h"
#include "ua_client_monitored_item.h"
#include "ua_client_observers.h"
#include "ua_client_subscription.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_response.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_expanded_node_id.h"
#include "ua_logger.h"
#include "ua_monitored_item_create_result.h"
#include "ua_publish_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_reference_description.h"
#include "ua_relative_path.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_status_change_notification.h"
#include "ua_status_code.h"
#include "ua_translated_node_id.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_typed_access.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_write_response.h"

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;
using ua::client::BrowseCursor;
using ua::client::Connection;
using ua::client::MonitoredItem;
using ua::client::MonitorRequest;
using ua::client::ReconnectPolicy;
using ua::client::Session;
using ua::client::Subscription;
using ua::client::SubscriptionConfig;
using ua::client::TranslatedNodeId;
using ua::client::TypedAccess;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

/// A single-result ReadResponse carrying @p dataValue, its ServiceResult @p serviceResult.
ua::ReadResponse make_read_response(
  ua::DataValue dataValue, StatusCode serviceResult = StatusCode{Status::Good})
{
  ua::ReadResponse response;
  response.response_header().service_result() = std::move(serviceResult);
  response.results().push_back(std::move(dataValue));
  return response;
}

/// Records what the SubscriptionObserver receives.
class RecordingSubscriptionObserver : public ua::client::SubscriptionObserver
{
public:
  void on_subscription_terminated(
    ua::IntegerId subscriptionId, StatusCode reason, std::shared_ptr<const ua::ErrorDetail>) override
  {
    std::lock_guard lock(mMutex);
    mTerminated.emplace_back(subscriptionId, std::move(reason));
    mCondition.notify_all();
  }

  /// Waits for the first termination; nullopt when none arrived in time.
  std::optional<std::pair<ua::IntegerId, StatusCode>> wait_for_termination()
  {
    std::unique_lock lock(mMutex);
    if (!mCondition.wait_for(lock, 2s, [this]() { return !mTerminated.empty(); }))
    {
      return std::nullopt;
    }
    return mTerminated.front();
  }

private:
  std::mutex mMutex;
  std::condition_variable mCondition;
  std::vector<std::pair<ua::IntegerId, StatusCode>> mTerminated;
};

/// Records the advisories the ConnectionObserver receives.
class RecordingConnectionObserver : public ua::client::ConnectionObserver
{
public:
  void on_advisory_diagnostic(const Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    std::lock_guard lock(mMutex);
    mAdvisories.push_back(std::move(detail));
    mCondition.notify_all();
  }

  /// Waits for an advisory whose ErrorDetail code is @p code; null when none arrived in time.
  std::shared_ptr<const ua::ErrorDetail> wait_for_advisory(const std::string& code)
  {
    std::unique_lock lock(mMutex);
    std::shared_ptr<const ua::ErrorDetail> found;
    mCondition.wait_for(lock,
      2s,
      [&]()
      {
        for (const auto& advisory : mAdvisories)
        {
          if (advisory && advisory->code == code)
          {
            found = advisory;
            return true;
          }
        }
        return false;
      });
    return found;
  }

private:
  std::mutex mMutex;
  std::condition_variable mCondition;
  std::vector<std::shared_ptr<const ua::ErrorDetail>> mAdvisories;
};

/// A live Active ConnectionImpl over FakeSessionOps plus the public handles under test.
class ClientStatusRoutingTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<RecordingSubscriptionObserver> mSubscriptionObserver =
    std::make_shared<RecordingSubscriptionObserver>();
  std::shared_ptr<RecordingConnectionObserver> mConnectionObserver =
    std::make_shared<RecordingConnectionObserver>();
  std::shared_ptr<ConnectionImpl> mConnection;

  /// Starts the Connection; @p bootstrap answers the bootstrap Read (namespace table and limits).
  void start(ua::ReadResponse bootstrap = ua::test_helpers::make_namespace_array_response())
  {
    mSession->read.set_result(Result<ua::ReadResponse>{std::move(bootstrap)});
    ConnectionConfig config;
    config.observers.subscription = mSubscriptionObserver;
    config.observers.connection = mConnectionObserver;
    mConnection = TA::create_with_ops(mRuntime.executor(),
      mSession,
      std::move(config),
      ua::Logger{},
      mReopen->as_ops(),
      Session::ActivateConfig{},
      fast_policy(),
      {});
    std::promise<VoidResult> started;
    auto future = started.get_future();
    mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
    ASSERT_TRUE(future.get().is_good());
  }

  void TearDown() override
  {
    if (!mConnection)
    {
      return;
    }
    std::promise<VoidResult> closed;
    auto future = closed.get_future();
    mConnection->close_async([&closed](VoidResult result) { closed.set_value(std::move(result)); });
    (void)future.wait_for(2s);
  }

  Connection make_connection()
  {
    return ConnectionHandleFactory::make_connection(mConnection);
  }

  TypedAccess make_typed_access()
  {
    return ConnectionHandleFactory::make_typed_access(mConnection);
  }

  /// Answers every Read after the bootstrap with @p response.
  void answer_reads_with(ua::ReadResponse response)
  {
    mSession->read.set_result(Result<ua::ReadResponse>{std::move(response)});
  }

  /// Answers the ValueRank / ArrayDimensions metadata Read a Value write issues first with a scalar shape.
  void answer_reads_with_scalar_shape(std::size_t count = 1)
  {
    mSession->read.set_result_fn(
      [count](const ua::ReadRequest&) -> Result<ua::ReadResponse>
      {
        ua::ReadResponse response;
        for (std::size_t i = 0; i < count; ++i)
        {
          response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{-1}}});
          response.results().push_back(ua::DataValue{});
        }
        return Result<ua::ReadResponse>{std::move(response)};
      });
  }

  /// Runs @p invoke and waits for its callback; nullopt when the callback did not run in time.
  template<typename Response, typename Invoke>
  std::optional<Result<Response>> await(Invoke invoke)
  {
    auto done = std::make_shared<std::promise<Result<Response>>>();
    auto future = done->get_future();
    invoke([done](Result<Response> result) { done->set_value(std::move(result)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      return std::nullopt;
    }
    return future.get();
  }
};

// ===================== Typed reads answer the combined code =====================

// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(ClientStatusRoutingTest, TypedReadHoldsAnUncertainValueWithItsCode)
{
  start();
  answer_reads_with(make_read_response(
    ua::DataValue{ua::Variant{std::int32_t{42}}, StatusCode{Status::UncertainInitialValue}}));

  auto connection = make_connection();
  auto result = await<std::int32_t>(
    [&](auto cb) { connection.read_value_async<std::int32_t>(ua::NodeId{0, 7}, std::move(cb)); });

  ASSERT_TRUE(result.has_value()) << "the callback ran";
  EXPECT_TRUE(result->is_uncertain());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::UncertainInitialValue}.value());
  EXPECT_EQ(result->value_or(0), 42) << "the decoded value is held with the Uncertain code";
}

// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(ClientStatusRoutingTest, TypedReadKeepsAGoodSubcodeOfTheDataValue)
{
  start();
  answer_reads_with(
    make_read_response(ua::DataValue{ua::Variant{std::int32_t{42}}, StatusCode{Status::GoodLocalOverride}}));

  auto connection = make_connection();
  auto result = await<std::int32_t>(
    [&](auto cb) { connection.read_value_async<std::int32_t>(ua::NodeId{0, 7}, std::move(cb)); });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_good());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::GoodLocalOverride}.value());
  EXPECT_EQ(result->value_or(0), 42);
}

// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(ClientStatusRoutingTest, TypedReadOfAnUncertainDataValueWithoutAValueHoldsNoValue)
{
  start();
  answer_reads_with(
    make_read_response(ua::DataValue{StatusCode{Status::UncertainNoCommunicationLastUsableValue}}));

  auto connection = make_connection();
  auto result = await<std::int32_t>(
    [&](auto cb) { connection.read_value_async<std::int32_t>(ua::NodeId{0, 7}, std::move(cb)); });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_uncertain()) << "the code is the DataValue's, not a decode failure";
  EXPECT_EQ(
    result->status_code().value(), StatusCode{Status::UncertainNoCommunicationLastUsableValue}.value());
  EXPECT_EQ(result->value_or(-1), -1) << "no value is held";
}

// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(ClientStatusRoutingTest, TypedReadOfABadDataValueIsBad)
{
  start();
  answer_reads_with(
    make_read_response(ua::DataValue{ua::Variant{std::int32_t{7}}, StatusCode{Status::BadDeviceFailure}}));

  auto connection = make_connection();
  auto result = await<std::int32_t>(
    [&](auto cb) { connection.read_value_async<std::int32_t>(ua::NodeId{0, 7}, std::move(cb)); });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_bad());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::BadDeviceFailure}.value());
}

// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(ClientStatusRoutingTest, TypedSyncReadHoldsAnUncertainValueAndTheThrowingFormThrows)
{
  start();
  answer_reads_with(make_read_response(
    ua::DataValue{ua::Variant{std::int32_t{42}}, StatusCode{Status::UncertainInitialValue}}));

  auto connection = make_connection();
  auto result = connection.try_read_value_sync<std::int32_t>(ua::NodeId{0, 7});
  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::UncertainInitialValue}.value());
  EXPECT_EQ(result.value_or(0), 42);

  EXPECT_THROW((void)connection.read_value_sync<std::int32_t>(ua::NodeId{0, 7}), ua::UaException)
    << "the throwing form has no place for an Uncertain code";
}

// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
// @relation(AC-CL-STATUS-ROUTING-01-A-SERVICE-RESULT-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, ReadServiceResultGoodSubcodeReachesTheTypedAndTheDataValueRead)
{
  start();
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    answer_reads_with(
      make_read_response(ua::DataValue{ua::Variant{std::int32_t{42}}}, StatusCode{serviceStatus}));

    auto connection = make_connection();
    auto typed = await<std::int32_t>(
      [&](auto cb) { connection.read_value_async<std::int32_t>(ua::NodeId{0, 7}, std::move(cb)); });
    ASSERT_TRUE(typed.has_value());
    EXPECT_EQ(typed->status_code().value(), StatusCode{serviceStatus}.value());
    EXPECT_EQ(typed->value_or(0), 42);

    auto dataValue =
      await<ua::DataValue>([&](auto cb) { connection.read_value_async(ua::NodeId{0, 7}, std::move(cb)); });
    ASSERT_TRUE(dataValue.has_value());
    EXPECT_EQ(dataValue->status_code().value(), StatusCode{serviceStatus}.value())
      << "the ServiceResult is on the outer Result, the value quality on the DataValue";
    EXPECT_EQ(dataValue->value().value(), ua::Variant{std::int32_t{42}});
  }
}

// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(ClientStatusRoutingTest, BulkTypedReadAnswersEachElementsCombinedCode)
{
  start();
  ua::ReadResponse response;
  response.results().push_back(
    ua::DataValue{ua::Variant{std::int32_t{10}}, StatusCode{Status::UncertainInitialValue}});
  response.results().push_back(
    ua::DataValue{ua::Variant{std::int32_t{20}}, StatusCode{Status::GoodLocalOverride}});
  response.results().push_back(ua::DataValue{StatusCode{Status::UncertainNoCommunicationLastUsableValue}});
  answer_reads_with(std::move(response));

  auto typed = make_typed_access();
  auto result = await<std::vector<Result<std::int32_t>>>(
    [&](auto cb)
    {
      typed.read_values_async<std::int32_t>(
        {ua::NodeId{0, 1}, ua::NodeId{0, 2}, ua::NodeId{0, 3}}, std::move(cb));
    });

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->is_good());
  const auto& elements = result->value();
  ASSERT_EQ(elements.size(), 3u);
  EXPECT_TRUE(elements[0].is_uncertain());
  EXPECT_EQ(elements[0].status_code().value(), StatusCode{Status::UncertainInitialValue}.value());
  EXPECT_EQ(elements[0].value_or(0), 10);
  EXPECT_EQ(elements[1].status_code().value(), StatusCode{Status::GoodLocalOverride}.value());
  EXPECT_EQ(elements[1].value_or(0), 20);
  EXPECT_TRUE(elements[2].is_uncertain());
  EXPECT_EQ(elements[2].value_or(-1), -1);
}

// @relation(AC-CL-STATUS-ROUTING-02-A-TYPED-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST_F(ClientStatusRoutingTest, BulkTypedReadThrowingFormThrowsForAnUncertainServiceResult)
{
  start();
  answer_reads_with(make_read_response(
    ua::DataValue{ua::Variant{std::int32_t{10}}}, StatusCode{Status::UncertainInitialValue}));

  auto typed = make_typed_access();
  auto result = typed.try_read_values_sync<std::int32_t>({ua::NodeId{0, 1}});
  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), StatusCode{Status::UncertainInitialValue}.value());

  EXPECT_THROW((void)typed.read_values_sync<std::int32_t>({ua::NodeId{0, 1}}), ua::UaException);
}

// ===================== Writes, Calls, TranslateBrowsePaths and Browse pages =====================

// @relation(AC-CL-STATUS-ROUTING-01-A-WRITES-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, WriteAttributeKeepsTheItemsGoodSubcode)
{
  start();
  answer_reads_with_scalar_shape();
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(StatusCode{Status::GoodClamped});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto cb)
    {
      typed.write_attribute_async(ua::NodeId{0, 10},
        ua::AttributeId::Value,
        ua::DataValue{ua::Variant{std::int32_t{123}}},
        std::move(cb));
    });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_good());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::GoodClamped}.value());
}

// @relation(AC-CL-STATUS-ROUTING-01-A-WRITES-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, WriteAttributeKeepsAnUncertainServiceResult)
{
  start();
  answer_reads_with_scalar_shape();
  ua::WriteResponse writeResponse;
  writeResponse.response_header().service_result() = StatusCode{Status::UncertainInitialValue};
  writeResponse.results().push_back(StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto cb)
    {
      typed.write_attribute_async(ua::NodeId{0, 10},
        ua::AttributeId::Value,
        ua::DataValue{ua::Variant{std::int32_t{123}}},
        std::move(cb));
    });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_uncertain());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::UncertainInitialValue}.value());
}

// @relation(AC-CL-STATUS-ROUTING-01-A-WRITES-GOOD-SUBCODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, WriteValuesKeepsEachItemsGoodSubcode)
{
  start();
  answer_reads_with_scalar_shape(2);
  ua::WriteResponse writeResponse;
  writeResponse.results().push_back(StatusCode{Status::GoodClamped});
  writeResponse.results().push_back(StatusCode{Status::Good});
  mSession->write.set_result(Result<ua::WriteResponse>{std::move(writeResponse)});

  auto typed = make_typed_access();
  std::vector<std::pair<ua::NodeId, ua::Variant>> pairs;
  pairs.emplace_back(ua::NodeId{0, 1}, ua::Variant{std::int32_t{1}});
  pairs.emplace_back(ua::NodeId{0, 2}, ua::Variant{std::int32_t{2}});
  auto result = await<std::vector<VoidResult>>(
    [&](auto cb) { typed.write_values_async(std::move(pairs), std::move(cb)); });

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->is_good());
  ASSERT_EQ(result->value().size(), 2u);
  EXPECT_EQ(result->value()[0].status_code().value(), StatusCode{Status::GoodClamped}.value());
  EXPECT_EQ(result->value()[1].status_code().value(), StatusCode{Status::Good}.value());
}

// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, CallKeepsTheServiceResultAndTheMethodsGoodSubcode)
{
  start();
  for (const ua::Status serviceStatus :
    {ua::Status::GoodResultsMayBeIncomplete, ua::Status::GoodLocalOverride})
  {
    SCOPED_TRACE(ua::StatusCode{serviceStatus}.value());
    for (const ua::Status methodStatus : {ua::Status::GoodPostActionFailed, ua::Status::GoodClamped})
    {
      SCOPED_TRACE(ua::StatusCode{methodStatus}.value());
      ua::CallMethodResult methodResult;
      methodResult.status_code() = StatusCode{methodStatus};
      methodResult.output_arguments().push_back(ua::Variant{std::int32_t{5}});
      ua::CallResponse response;
      response.response_header().service_result() = StatusCode{serviceStatus};
      response.results().push_back(std::move(methodResult));
      mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

      auto typed = make_typed_access();
      auto result = await<ua::CallResult>(
        [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

      ASSERT_TRUE(result.has_value());
      EXPECT_EQ(result->status_code().value(), StatusCode{serviceStatus}.value())
        << "the ServiceResult is on the outer Result";
      ASSERT_TRUE(result->is_good());
      const ua::CallResult& inner = result->value();
      EXPECT_EQ(inner.status_code().value(), StatusCode{methodStatus}.value())
        << "the method's statusCode is on the inner Result";
      ASSERT_EQ(inner.value().output_arguments().size(), 1U);
      EXPECT_EQ(inner.value().output_arguments()[0], ua::Variant{std::int32_t{5}});
    }
  }
}

// @relation(AC-CL-STATUS-ROUTING-01-A-METHOD-CALLS-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, CallHoldsTheOutputsWithAnUncertainMethodCode)
{
  start();
  ua::CallMethodResult methodResult;
  methodResult.status_code() = StatusCode{Status::UncertainInitialValue};
  methodResult.output_arguments().push_back(ua::Variant{std::int32_t{111}});
  ua::CallResponse response;
  response.results().push_back(std::move(methodResult));
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->is_good());
  const ua::CallResult& inner = result->value();
  EXPECT_TRUE(inner.is_uncertain());
  EXPECT_EQ(inner.status_code().value(), StatusCode{Status::UncertainInitialValue}.value());
  ASSERT_EQ(inner.value().output_arguments().size(), 1u) << "the outputs are held with the Uncertain code";
  EXPECT_EQ(inner.value().output_arguments()[0], ua::Variant{std::int32_t{111}});
}

// @relation(AC-CL-STATUS-ROUTING-01-A-BROWSE-OR-TRANSLATE-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, TranslateHoldsTheTargetsWithThePathsUncertainCode)
{
  start();
  ua::BrowsePathResult perPath;
  perPath.status_code() = StatusCode{Status::UncertainReferenceOutOfServer};
  ua::BrowsePathTarget target;
  target.target_id() = ua::ExpandedNodeId{ua::NodeId{2, 77}};
  target.remaining_path_index() = 0xFFFFFFFFU;
  perPath.targets().push_back(std::move(target));
  ua::TranslateBrowsePathsToNodeIdsResponse response;
  response.results().push_back(std::move(perPath));
  mSession->translateBrowsePaths.set_result(
    Result<ua::TranslateBrowsePathsToNodeIdsResponse>{std::move(response)});

  auto typed = make_typed_access();
  auto result = await<std::vector<TranslatedNodeId>>([&](auto cb)
    { typed.translate_browse_path_async(ua::NodeId{0, 84}, ua::RelativePath{}, std::move(cb)); });

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->is_uncertain());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::UncertainReferenceOutOfServer}.value());
  EXPECT_EQ(result->value_or(std::vector<TranslatedNodeId>{}).size(), 1u);
}

// @relation(AC-CL-STATUS-ROUTING-01-A-BROWSE-OR-TRANSLATE-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, BrowseCursorEntryCarriesThePagesGoodSubcode)
{
  start();
  ua::BrowseResult page;
  page.status_code() = StatusCode{Status::GoodResultsMayBeIncomplete};
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = ua::NodeId{2, 5};
  reference.is_forward() = true;
  page.references().push_back(std::move(reference));
  ua::BrowseResponse response;
  response.results().push_back(std::move(page));
  mSession->browse.set_result(Result<ua::BrowseResponse>{std::move(response)});

  auto typed = make_typed_access();
  BrowseCursor cursor = typed.browse(ua::NodeId{0, 85});
  auto entry = await<BrowseCursor::Entry>([&](auto cb) { cursor.next_async(std::move(cb)); });

  ASSERT_TRUE(entry.has_value());
  ASSERT_TRUE(entry->is_good());
  EXPECT_EQ(entry->status_code().value(), StatusCode{Status::GoodResultsMayBeIncomplete}.value())
    << "the page's Good subcode is the status of each entry it yields";
}

// ===================== A helper that decodes a value checks its status =====================

// A Value write first reads the Variable's ValueRank and ArrayDimensions and decides on them; an Uncertain
// ValueRank is refused (Bad_InternalError, ReadAnswerUncertain) and no Write is sent.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST_F(ClientStatusRoutingTest, AnUncertainValueRankRefusesTheValueWriteBeforeItIsSent)
{
  start();
  mSession->read.set_result_fn(
    [](const ua::ReadRequest&) -> Result<ua::ReadResponse>
    {
      ua::ReadResponse response;
      response.results().push_back(
        ua::DataValue{ua::Variant{std::int32_t{-1}}, StatusCode{Status::UncertainLastUsableValue}});
      response.results().push_back(ua::DataValue{});
      return Result<ua::ReadResponse>{std::move(response)};
    });

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto cb)
    {
      typed.write_attribute_async(ua::NodeId{0, 10},
        ua::AttributeId::Value,
        ua::DataValue{ua::Variant{std::int32_t{1}}},
        std::move(cb));
    });

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->status_code().value(), StatusCode{Status::BadInternalError}.value());
  ASSERT_NE(result->shared_detail(), nullptr);
  EXPECT_EQ(result->shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_EQ(mSession->write.call_count(), 0u) << "the write is not sent on an Uncertain shape";
}

// ===================== A chunked request keeps every chunk's ServiceResult =====================

// Answers the bootstrap Read with MaxNodesPerRead 2; each chunk Read answers one Int32 per node, its
// ServiceResult @p codeFor gives for the chunk's first node.
template<typename CodeFor>
void install_chunk_reads(FakeSessionOps& session, CodeFor codeFor)
{
  session.read.set_result_fn(
    [codeFor](const ua::ReadRequest& request) -> Result<ua::ReadResponse>
    {
      if (!request.nodes_to_read().empty() &&
          request.nodes_to_read()[0].node_id() == ua::NodeId{ua::VariableId::Server_NamespaceArray})
      {
        return Result<ua::ReadResponse>{ua::test_helpers::make_namespace_array_response(
          {"http://opcfoundation.org/UA/", "urn:test:connection"},
          std::nullopt,
          {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})};
      }
      ua::ReadResponse response;
      if (!request.nodes_to_read().empty())
      {
        response.response_header().service_result() =
          codeFor(request.nodes_to_read()[0].node_id().identifier().get_numeric());
      }
      for (const auto& node : request.nodes_to_read())
      {
        response.results().push_back(
          ua::DataValue{ua::Variant{static_cast<std::int32_t>(node.node_id().identifier().get_numeric())}});
      }
      return Result<ua::ReadResponse>{std::move(response)};
    });
}

ua::ReadRequest make_numeric_read(std::uint32_t base, std::size_t count)
{
  ua::ReadRequest request;
  for (std::size_t i = 0; i < count; ++i)
  {
    ua::ReadValueId node;
    node.node_id() = ua::NodeId{static_cast<std::uint32_t>(base + i)};
    node.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
    request.nodes_to_read().push_back(std::move(node));
  }
  return request;
}

// @relation(AC-CL-STATUS-ROUTING-01-A-CHUNKED-REQUEST-KEEPS-EVERY-CHUNKS-SERVICE-RESULT, scope=function)
TEST_F(ClientStatusRoutingTest, ALaterChunksGoodSubcodeIsTheMergedServiceResult)
{
  install_chunk_reads(*mSession, [](std::uint32_t) { return StatusCode{Status::Good}; });
  ConnectionConfig config;
  mConnection = TA::create_with_ops(mRuntime.executor(),
    mSession,
    std::move(config),
    ua::Logger{},
    mReopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    {});
  std::promise<VoidResult> started;
  auto startedFuture = started.get_future();
  mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
  ASSERT_TRUE(startedFuture.get().is_good());

  for (const Status chunkGoodStatus : {Status::GoodResultsMayBeIncomplete, Status::GoodLocalOverride})
  {
    SCOPED_TRACE(StatusCode{chunkGoodStatus}.value());
    install_chunk_reads(*mSession,
      [chunkGoodStatus](std::uint32_t first)
      {
        if (first == 102)
        {
          return StatusCode{chunkGoodStatus};
        }
        return StatusCode{Status::Good};
      });
    auto result = await<ua::ReadResponse>(
      [&](auto callback) { mConnection->read_async(make_numeric_read(100, 5), std::move(callback)); });

    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result->is_bad());
    ASSERT_EQ(result->value().results().size(), 5u);
    EXPECT_EQ(result->value().response_header().service_result().value(), StatusCode{chunkGoodStatus}.value())
      << "the second chunk's Good subcode is not lost to the first chunk's plain Good";
    const std::vector<std::int32_t> expected{100, 101, 102, 103, 104};
    for (std::size_t index = 0; index < expected.size(); ++index)
    {
      EXPECT_EQ(result->value().results()[index].value(), ua::Variant{expected[index]});
    }
  }
}

// @relation(AC-CL-STATUS-ROUTING-01-A-CHUNKED-REQUEST-KEEPS-EVERY-CHUNKS-SERVICE-RESULT, scope=function)
TEST_F(ClientStatusRoutingTest, AnUncertainChunkOutranksAGoodSubcodeInTheMergedServiceResult)
{
  install_chunk_reads(*mSession, [](std::uint32_t) { return StatusCode{Status::Good}; });
  mConnection = TA::create_with_ops(mRuntime.executor(),
    mSession,
    ConnectionConfig{},
    ua::Logger{},
    mReopen->as_ops(),
    Session::ActivateConfig{},
    fast_policy(),
    {});
  std::promise<VoidResult> started;
  auto startedFuture = started.get_future();
  mConnection->start_async([&started](VoidResult result) { started.set_value(std::move(result)); });
  ASSERT_TRUE(startedFuture.get().is_good());

  for (const Status chunkGoodStatus : {Status::GoodResultsMayBeIncomplete, Status::GoodLocalOverride})
  {
    SCOPED_TRACE(StatusCode{chunkGoodStatus}.value());
    install_chunk_reads(*mSession,
      [chunkGoodStatus](std::uint32_t first)
      {
        if (first == 104)
        {
          return StatusCode{Status::UncertainInitialValue};
        }
        if (chunkGoodStatus == Status::GoodLocalOverride && first == 100)
        {
          return StatusCode{chunkGoodStatus};
        }
        if (chunkGoodStatus == Status::GoodResultsMayBeIncomplete && first == 102)
        {
          return StatusCode{chunkGoodStatus};
        }
        return StatusCode{Status::Good};
      });
    auto result = await<ua::ReadResponse>(
      [&](auto callback) { mConnection->read_async(make_numeric_read(100, 5), std::move(callback)); });

    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(result->is_bad());
    ASSERT_EQ(result->value().results().size(), 5u);
    EXPECT_EQ(result->value().response_header().service_result().value(),
      StatusCode{Status::UncertainInitialValue}.value());
    const std::vector<std::int32_t> expected{100, 101, 102, 103, 104};
    for (std::size_t index = 0; index < expected.size(); ++index)
    {
      EXPECT_EQ(result->value().results()[index].value(), ua::Variant{expected[index]});
    }
  }
}

// ===================== Subscriptions and MonitoredItems =====================

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, SubscriptionAndMonitoredItemCreationCodesReachTheHandles)
{
  start();
  mSession->publish.set_hold(true);  // no Publish traffic: the test asserts creation only
  ua::CreateSubscriptionResponse subscriptionResponse;
  subscriptionResponse.response_header().service_result() = StatusCode{Status::GoodResultsMayBeIncomplete};
  subscriptionResponse.subscription_id() = 1;
  subscriptionResponse.revised_publishing_interval() = 500.0;
  subscriptionResponse.revised_lifetime_count() = 60;
  subscriptionResponse.revised_max_keep_alive_count() = 20;
  mSession->createSubscription.set_result(
    Result<ua::CreateSubscriptionResponse>{std::move(subscriptionResponse)});
  ua::CreateMonitoredItemsResponse itemsResponse;
  ua::MonitoredItemCreateResult item;
  item.status_code() = StatusCode{Status::GoodOverload};
  item.monitored_item_id() = 9;
  itemsResponse.results().push_back(std::move(item));
  mSession->createMonitoredItems.set_result(
    Result<ua::CreateMonitoredItemsResponse>{std::move(itemsResponse)});

  auto connection = make_connection();
  auto subscription = await<Subscription>(
    [&](auto cb) { connection.create_subscription_async(SubscriptionConfig{}, std::move(cb)); });
  ASSERT_TRUE(subscription.has_value());
  ASSERT_TRUE(subscription->is_good());
  EXPECT_EQ(subscription->status_code().value(), StatusCode{Status::GoodResultsMayBeIncomplete}.value());

  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 10};
  auto monitored = await<MonitoredItem>(
    [&](auto cb)
    {
      subscription->value().monitor_async(
        std::move(request), [](ua::client::DataChangeEvent) {}, std::move(cb));
    });
  ASSERT_TRUE(monitored.has_value());
  ASSERT_TRUE(monitored->is_good());
  EXPECT_EQ(monitored->status_code().value(), StatusCode{Status::GoodOverload}.value());
}

/// A PublishResponse for @p subscriptionId at sequence number 1 carrying one StatusChangeNotification.
ua::PublishResponse make_status_change(std::uint32_t subscriptionId, StatusCode status)
{
  ua::PublishResponse response;
  response.subscription_id() = subscriptionId;
  response.notification_message().sequence_number() = 1;
  auto statusChange = std::make_unique<ua::StatusChangeNotification>();
  statusChange->status() = std::move(status);
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(statusChange);
  response.notification_message().notification_data().push_back(std::move(ref));
  return response;
}

// @relation(AC-CL-STATUS-ROUTING-01-SUBSCRIPTION-TRANSFERRED-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, SubscriptionTransferredEndsTheSubscriptionAndReachesTheObserver)
{
  start();
  mSession->publish.set_hold(true);
  auto connection = make_connection();
  auto subscription = await<Subscription>(
    [&](auto cb) { connection.create_subscription_async(SubscriptionConfig{}, std::move(cb)); });
  ASSERT_TRUE(subscription.has_value());
  ASSERT_FALSE(subscription->is_bad());

  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (mSession->publish.pending_count() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(1ms);
  }
  ASSERT_GT(mSession->publish.pending_count(), 0u) << "the pump issued a Publish";
  mSession->publish.fire_next(
    Result<ua::PublishResponse>{make_status_change(1, StatusCode{Status::GoodSubscriptionTransferred})});

  const auto terminated = mSubscriptionObserver->wait_for_termination();
  ASSERT_TRUE(terminated.has_value()) << "the Subscription no longer exists on this Session";
  EXPECT_EQ(terminated->first, 1u);
  EXPECT_EQ(terminated->second.value(), StatusCode{Status::GoodSubscriptionTransferred}.value())
    << "the server's code reaches the application unchanged";
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(ClientStatusRoutingTest, AnotherStatusChangeReachesTheApplicationAsAnAdvisory)
{
  start();
  mSession->publish.set_hold(true);
  auto connection = make_connection();
  auto subscription = await<Subscription>(
    [&](auto cb) { connection.create_subscription_async(SubscriptionConfig{}, std::move(cb)); });
  ASSERT_TRUE(subscription.has_value());
  ASSERT_FALSE(subscription->is_bad());

  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (mSession->publish.pending_count() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(1ms);
  }
  ASSERT_GT(mSession->publish.pending_count(), 0u);
  mSession->publish.fire_next(
    Result<ua::PublishResponse>{make_status_change(1, StatusCode{Status::BadShutdown})});

  const auto advisory = mConnectionObserver->wait_for_advisory("SubscriptionStatusChange");
  ASSERT_NE(advisory, nullptr) << "a status change that does not end the Subscription is an advisory";
  EXPECT_EQ(advisory->innerStatus, StatusCode{Status::BadShutdown}.value())
    << "the server's code is the advisory's cause";
  EXPECT_FALSE(mSubscriptionObserver->wait_for_termination().has_value()) << "the Subscription is not ended";
}

// ===================== An Uncertain ServiceFault completes every facade's callback =====================

// A ServiceFault reaches a facade as a result with the fault's code and no response.
template<typename Response>
Result<Response> uncertain_fault()
{
  return Result<Response>{StatusCode{Status::UncertainNoCommunicationLastUsableValue}};
}

constexpr std::uint32_t uncertainFaultCode = 0x408F0000U;  // Uncertain_NoCommunicationLastUsableValue

// @relation(AC-CL-STATUS-ROUTING-03-AN-UNCERTAIN-SERVICE-FAULT-COMPLETES-THE-CALLBACK, scope=function)
TEST_F(ClientStatusRoutingTest, AnUncertainReadFaultCompletesTheReadCallbacks)
{
  start();
  ASSERT_EQ(StatusCode{Status::UncertainNoCommunicationLastUsableValue}.value(), uncertainFaultCode);
  mSession->read.set_result(uncertain_fault<ua::ReadResponse>());

  auto connection = make_connection();
  auto dataValue =
    await<ua::DataValue>([&](auto cb) { connection.read_value_async(ua::NodeId{0, 7}, std::move(cb)); });
  ASSERT_TRUE(dataValue.has_value()) << "the DataValue read's callback ran";
  EXPECT_EQ(dataValue->status_code().value(), uncertainFaultCode);

  auto typed = await<std::int32_t>(
    [&](auto cb) { connection.read_value_async<std::int32_t>(ua::NodeId{0, 7}, std::move(cb)); });
  ASSERT_TRUE(typed.has_value()) << "the typed read's callback ran";
  EXPECT_EQ(typed->status_code().value(), uncertainFaultCode);
  EXPECT_EQ(typed->value_or(-1), -1);
}

// @relation(AC-CL-STATUS-ROUTING-03-AN-UNCERTAIN-SERVICE-FAULT-COMPLETES-THE-CALLBACK, scope=function)
TEST_F(ClientStatusRoutingTest, AnUncertainWriteFaultCompletesTheWriteCallback)
{
  start();
  answer_reads_with_scalar_shape();
  mSession->write.set_result(uncertain_fault<ua::WriteResponse>());

  auto typed = make_typed_access();
  auto result = await<void>(
    [&](auto cb)
    {
      typed.write_attribute_async(ua::NodeId{0, 10},
        ua::AttributeId::Value,
        ua::DataValue{ua::Variant{std::int32_t{1}}},
        std::move(cb));
    });

  ASSERT_TRUE(result.has_value()) << "the write's callback ran";
  EXPECT_EQ(result->status_code().value(), uncertainFaultCode);
}

// @relation(AC-CL-STATUS-ROUTING-03-AN-UNCERTAIN-SERVICE-FAULT-COMPLETES-THE-CALLBACK, scope=function)
TEST_F(ClientStatusRoutingTest, AnUncertainCallFaultCompletesTheCallCallback)
{
  start();
  mSession->call.set_result(uncertain_fault<ua::CallResponse>());

  auto typed = make_typed_access();
  auto result = await<ua::CallResult>(
    [&](auto cb) { typed.call_method_async(ua::NodeId{0, 1}, ua::NodeId{0, 2}, {}, std::move(cb)); });

  ASSERT_TRUE(result.has_value()) << "the call's callback ran";
  EXPECT_EQ(result->status_code().value(), uncertainFaultCode);
}

// @relation(AC-CL-STATUS-ROUTING-03-AN-UNCERTAIN-SERVICE-FAULT-COMPLETES-THE-CALLBACK, scope=function)
TEST_F(ClientStatusRoutingTest, AnUncertainBrowseFaultCompletesTheBrowseAndTranslateCallbacks)
{
  start();
  mSession->browse.set_result(uncertain_fault<ua::BrowseResponse>());
  mSession->translateBrowsePaths.set_result(uncertain_fault<ua::TranslateBrowsePathsToNodeIdsResponse>());

  auto typed = make_typed_access();
  BrowseCursor cursor = typed.browse(ua::NodeId{0, 85});
  auto entry = await<BrowseCursor::Entry>([&](auto cb) { cursor.next_async(std::move(cb)); });
  ASSERT_TRUE(entry.has_value()) << "the browse cursor's callback ran";
  EXPECT_EQ(entry->status_code().value(), uncertainFaultCode);

  auto translated = await<std::vector<TranslatedNodeId>>([&](auto cb)
    { typed.translate_browse_path_async(ua::NodeId{0, 84}, ua::RelativePath{}, std::move(cb)); });
  ASSERT_TRUE(translated.has_value()) << "the translate's callback ran";
  EXPECT_EQ(translated->status_code().value(), uncertainFaultCode);
}

}  // namespace
