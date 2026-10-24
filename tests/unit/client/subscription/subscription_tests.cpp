// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the tier-1 public ua::client::Subscription handle and its interaction with the real
// connection-lifetime DataChangeMonitoredItemOwner, over the FakeSessionOps tier-0 interface (client design
// section 7.4).
//
// Pinned:
//   - create through Subscriptions returns a typed Subscription snapshot (id + revised interval + enabled);
//   - monitor_async returns a DataChange MonitoredItem (kind/node/handle) and increments item_count;
//   - a live Publish DataChange is delivered to the callback as a decoded DataChangeEvent (node/attr/value);
//   - the returned MonitoredItem's self-action delete routes through the REAL owner to the tier-0 session;
//   - subscription lifecycle (modify / set_publishing_mode updates the flag / close) reaches the session;
//   - set_triggering with an unresolved handle fails locally with Bad_MonitoredItemIdInvalid.
//
// Falsifiability: a handle that dropped a forward fails the call_count assertion; an owner that never
// registered routing fails DeleteReachesTierZero; a broken DataChangeEvent adapter fails the delivery test.
//
// @verifies CL-MI-003
// @relation(CL-MI-003, scope=file)
// @verifies CL-MI-022
// @relation(CL-MI-022, scope=file)

#include "fake_session_ops.h"

#include "async_test_runtime.h"

#include "ua_client_subscription.h"
#include "ua_client_observers.h"
#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_data_change_monitored_item_owner.h"
#include "ua_type_resolver.h"

// The notification assembler that groups a Publish cycle's notifications by type is the SERVER-side
// Subscription, which links into this same unit-test binary. It is driven directly below so that the
// grouping observed is the product's, not a fabricated PublishResponse's.
#include "ua_monitored_item.h"
#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"

#include "ua_call_response.h"
#include "ua_create_subscription_response.h"
#include "ua_data_change_notification.h"
#include "ua_delete_monitored_items_response.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_event_field_list.h"
#include "ua_event_notification_list.h"
#include "ua_monitored_item_notification.h"
#include "ua_method_id.h"
#include "ua_memory_stream.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_modify_subscription_response.h"
#include "ua_monitored_item_modify_result.h"
#include "ua_monitoring_mode.h"
#include "ua_object_id.h"
#include "ua_publish_response.h"
#include "ua_set_monitoring_mode_response.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_status.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_unknown_structure.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;
using ua::Result;
using ua::Status;
using ua::VoidResult;
using ua::client::Connection;
using ua::client::ConnectionObserver;
using ua::client::DataChangeEvent;
using ua::client::MonitoredItem;
using ua::client::MonitoredItemKind;
using ua::client::MonitoredItemResult;
using ua::client::MonitorRequest;
using ua::client::ReconnectPolicy;
using ua::client::Session;
using ua::client::Subscription;
using ua::client::SubscriptionConfig;
using ua::client::detail::ConnectionConfig;
using ua::client::detail::ConnectionHandleFactory;
using ua::client::detail::ConnectionImpl;
using ua::client::detail::ConnectionImplTestAccess;
using ua::client::detail::DataChangeMonitoredItemOwner;
using ua::client::detail::RegistrationOutcome;
using ua::client::detail::UserTypeRegistration;
using ua::test_helpers::FakeReopen;
using ua::test_helpers::FakeSessionOps;

using TA = ConnectionImplTestAccess;

class CapturingAdvisoryObserver : public ConnectionObserver
{
public:
  void on_advisory_diagnostic(const Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    {
      std::lock_guard lock(mMutex);
      mLastDetail = std::move(detail);
    }
    mCount.fetch_add(1);
  }

  [[nodiscard]] std::size_t count() const noexcept
  {
    return mCount.load();
  }

  [[nodiscard]] std::shared_ptr<const ua::ErrorDetail> last_detail() const
  {
    std::lock_guard lock(mMutex);
    return mLastDetail;
  }

private:
  std::atomic<std::size_t> mCount{0};
  mutable std::mutex mMutex;
  std::shared_ptr<const ua::ErrorDetail> mLastDetail;
};

ReconnectPolicy fast_policy()
{
  ReconnectPolicy policy;
  policy.backoff.base = std::chrono::milliseconds{1};
  policy.backoff.max = std::chrono::milliseconds{1};
  policy.backoff.jitterPct = 0.0;
  return policy;
}

// A single-good-item StatusCode response (DeleteMonitoredItems / SetPublishingMode / DeleteSubscriptions).
template<class Response>
Response make_status_response()
{
  Response response;
  response.results().push_back(ua::StatusCode{Status::Good});
  return response;
}

ua::CallResponse make_get_monitored_items_response(
  ua::StatusCode status, ua::Variant serverHandles = {}, ua::Variant clientHandles = {})
{
  ua::CallMethodResult method;
  method.status_code() = std::move(status);
  if (!serverHandles.empty())
  {
    method.output_arguments().push_back(std::move(serverHandles));
    method.output_arguments().push_back(std::move(clientHandles));
  }
  ua::CallResponse response;
  response.results().push_back(std::move(method));
  return response;
}

// One live DataChange notification (clientHandle -> Int32) for a Publish delivery.
ua::PublishResponse make_publish_datachange(
  std::uint32_t subscriptionId, std::uint32_t sequenceNumber, std::uint32_t clientHandle, std::int32_t value)
{
  ua::PublishResponse response;
  response.subscription_id() = subscriptionId;
  response.notification_message().sequence_number() = sequenceNumber;
  auto dataChange = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  item.value() = ua::DataValue{ua::Variant{value}};
  dataChange->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(dataChange);
  response.notification_message().notification_data().push_back(std::move(ref));
  return response;
}

ua::PublishResponse make_publish_datachange(
  std::uint32_t subscriptionId, std::uint32_t sequenceNumber, std::uint32_t clientHandle, ua::Variant value)
{
  ua::PublishResponse response;
  response.subscription_id() = subscriptionId;
  response.notification_message().sequence_number() = sequenceNumber;
  auto dataChange = std::make_unique<ua::DataChangeNotification>();
  ua::MonitoredItemNotification item;
  item.client_handle() = clientHandle;
  item.value() = ua::DataValue{std::move(value)};
  dataChange->monitored_items().push_back(std::move(item));
  ua::RefStructure<ua::Structure> ref;
  ref.inner_unique_ptr() = std::move(dataChange);
  response.notification_message().notification_data().push_back(std::move(ref));
  return response;
}

ua::Variant make_argument_opaque_variant()
{
  ua::Argument argument;
  argument.name() = "Speed";
  argument.data_type() = ua::NodeId{0, 11U};
  argument.value_rank() = -1;

  ua::memory_stream_device::Dynamic device;
  ua::MemoryStream stream{device};
  const ua::EncodingLimits limits = ua::make_encoding_limits(ua::ApplicationConfig::load_default());
  ua::UaBinaryEncoder encoder{ua::CodecNamespaceContext{}, stream};
  encoder.encode(limits.stack_depth(), &argument);
  stream.seek_from_start(0);
  ua::UaBinaryDecoder decoder{ua::StructureResolver{}, stream, limits};
  ua::unique_ptr<ua::Structure> opaque;
  decoder.decode(limits.stack_depth(), opaque);
  return ua::Variant{std::move(opaque)};
}

// A live Active ConnectionImpl + public Connection wrapping it, with a scripted CreateSubscription id 42.
class SubscriptionHandleTest : public ::testing::Test
{
protected:
  ua::test_helpers::AsyncTestRuntime mRuntime;
  std::shared_ptr<FakeSessionOps> mSession = std::make_shared<FakeSessionOps>();
  std::shared_ptr<FakeReopen> mReopen = std::make_shared<FakeReopen>();
  std::shared_ptr<ConnectionImpl> mConnection;

  void SetUp() override
  {
    mSession->read.set_result(Result<ua::ReadResponse>{
      ua::test_helpers::make_namespace_array_response({"http://opcfoundation.org/UA/"})});
    ua::CreateSubscriptionResponse createResponse;
    createResponse.subscription_id() = 42;
    createResponse.revised_publishing_interval() = 480.0;
    mSession->createSubscription.set_result(
      Result<ua::CreateSubscriptionResponse>{std::move(createResponse)});
    mSession->deleteMonitoredItems.set_result(
      Result<ua::DeleteMonitoredItemsResponse>{make_status_response<ua::DeleteMonitoredItemsResponse>()});
    mSession->setPublishingMode.set_result(
      Result<ua::SetPublishingModeResponse>{make_status_response<ua::SetPublishingModeResponse>()});
    mSession->deleteSubscriptions.set_result(
      Result<ua::DeleteSubscriptionsResponse>{make_status_response<ua::DeleteSubscriptionsResponse>()});

    mConnection = TA::create_with_ops(mRuntime.executor(),
      mSession,
      ConnectionConfig{},
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

  Connection make_connection()
  {
    return ConnectionHandleFactory::make_connection(mConnection);
  }

  Subscription make_subscription()
  {
    auto connection = make_connection();
    return connection.subscriptions().create_sync(SubscriptionConfig{500.0});
  }

  void register_argument_type()
  {
    UserTypeRegistration registration;
    registration.namespaceUri = "http://opcfoundation.org/UA/";
    registration.dataTypeIdentifier = ua::NodeId{0, 296U};
    registration.binaryEncodingIdentifier = ua::NodeId{ua::Argument::defaultBinaryEncodingId};
    registration.decoder = std::make_shared<ua::Argument>();

    std::promise<Result<std::vector<RegistrationOutcome>>> registered;
    auto future = registered.get_future();
    mConnection->type_resolver()->register_types_async(
      {std::move(registration)}, [&registered](auto result) { registered.set_value(std::move(result)); });
    auto result = future.get();
    ASSERT_TRUE(result.is_good());
    ASSERT_EQ(result.value().size(), 1U);
    ASSERT_TRUE(result.value()[0].status.is_good());
  }

  template<class Predicate>
  static void wait_until(Predicate predicate, const char* what)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!predicate())
    {
      ASSERT_LT(std::chrono::steady_clock::now(), deadline) << "timed out waiting for " << what;
      std::this_thread::sleep_for(1ms);
    }
  }
};

// --- create returns a typed snapshot ---

TEST_F(SubscriptionHandleTest, CreateReturnsTypedHandleWithSnapshot)
{
  auto subscription = make_subscription();
  EXPECT_EQ(subscription.server_subscription_id(), 42u);
  EXPECT_EQ(subscription.publishing_interval(), 480.0) << "handle exposes the server-revised interval";
  EXPECT_TRUE(subscription.is_publishing_enabled());
  EXPECT_EQ(subscription.item_count(), 0u);
}

// --- monitor returns a DataChange MonitoredItem ---

TEST_F(SubscriptionHandleTest, MonitorReturnsDataChangeItemAndCountsIt)
{
  auto subscription = make_subscription();
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};

  const auto result = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
  ASSERT_TRUE(result.is_good());
  const auto& item = result.value();
  EXPECT_EQ(item.kind(), MonitoredItemKind::DataChange);
  EXPECT_EQ(item.node_id(), (ua::NodeId{2, 7}));
  EXPECT_NE(item.client_handle(), 0u) << "a Connection-unique clientHandle is allocated (CL-MI-003)";
  EXPECT_EQ(subscription.item_count(), 1u);
  EXPECT_EQ(mSession->createMonitoredItems.call_count(), 1u);
}

// @verifies CL-BASE-006
// @relation(CL-BASE-006, scope=function)
TEST_F(SubscriptionHandleTest, GetMonitoredItemsUsesOwningConnectionAndDecodesParallelHandles)
{
  mSession->call.set_result(
    Result<ua::CallResponse>{make_get_monitored_items_response(ua::StatusCode{Status::Good},
      ua::Variant{ua::Array<std::uint32_t>{101, 102}},
      ua::Variant{ua::Array<std::uint32_t>{201, 202}})});
  auto subscription = make_subscription();

  auto result = subscription.try_get_monitored_items_sync();

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().serverHandles, (std::vector<ua::IntegerId>{101, 102}));
  EXPECT_EQ(result.value().clientHandles, (std::vector<ua::IntegerId>{201, 202}));
  ASSERT_EQ(mSession->call.call_count(), 1u);
  const auto requests = mSession->call.requests();
  ASSERT_EQ(requests.back().methods_to_call().size(), 1u);
  const auto& method = requests.back().methods_to_call()[0];
  EXPECT_EQ(method.object_id(), (ua::NodeId{ua::ObjectId::Server}));
  EXPECT_EQ(method.method_id(), (ua::NodeId{ua::MethodId::Server_GetMonitoredItems}));
  ASSERT_EQ(method.input_arguments().size(), 1u);
  EXPECT_EQ(method.input_arguments()[0].to<std::uint32_t>().value(), 42u);
}

// @verifies CL-BASE-006
// @relation(CL-BASE-006, scope=function)
TEST_F(SubscriptionHandleTest, GetMonitoredItemsSurfacesMethodFailureWithOwningSubscriptionDetail)
{
  mSession->call.set_result(
    Result<ua::CallResponse>{make_get_monitored_items_response(ua::StatusCode{Status::BadUserAccessDenied})});
  auto subscription = make_subscription();

  auto result = subscription.try_get_monitored_items_sync();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadUserAccessDenied});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "GetMonitoredItemsMethodFailed");
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.subscription.get_monitored_items");
}

// @verifies CL-BASE-006
// @relation(CL-BASE-006, scope=function)
TEST_F(SubscriptionHandleTest, GetMonitoredItemsRejectsMismatchedHandleArrayLengths)
{
  mSession->call.set_result(
    Result<ua::CallResponse>{make_get_monitored_items_response(ua::StatusCode{Status::Good},
      ua::Variant{ua::Array<std::uint32_t>{101, 102}},
      ua::Variant{ua::Array<std::uint32_t>{201}})});
  auto subscription = make_subscription();

  auto result = subscription.try_get_monitored_items_sync();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadDecodingError});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "GetMonitoredItemsArrayLengthMismatch");
}

// @verifies CL-BASE-007
// @relation(CL-BASE-007, scope=function)
TEST_F(SubscriptionHandleTest, ResendDataUsesOwningConnectionAndSubscriptionId)
{
  mSession->call.set_result(
    Result<ua::CallResponse>{make_get_monitored_items_response(ua::StatusCode{Status::Good})});
  auto subscription = make_subscription();

  auto result = subscription.try_resend_data_sync();

  ASSERT_TRUE(result.is_good());
  ASSERT_EQ(mSession->call.call_count(), 1u);
  const auto requests = mSession->call.requests();
  ASSERT_EQ(requests.back().methods_to_call().size(), 1u);
  const auto& method = requests.back().methods_to_call()[0];
  EXPECT_EQ(method.object_id(), (ua::NodeId{ua::ObjectId::Server}));
  EXPECT_EQ(method.method_id(), (ua::NodeId{ua::MethodId::Server_ResendData}));
  ASSERT_EQ(method.input_arguments().size(), 1u);
  EXPECT_EQ(method.input_arguments()[0].to<std::uint32_t>().value(), 42u);
}

// @verifies CL-BASE-007
// @relation(CL-BASE-007, scope=function)
TEST_F(SubscriptionHandleTest, ResendDataSurfacesMethodFailureWithOwningSubscriptionDetail)
{
  mSession->call.set_result(
    Result<ua::CallResponse>{make_get_monitored_items_response(ua::StatusCode{Status::BadUserAccessDenied})});
  auto subscription = make_subscription();

  auto result = subscription.try_resend_data_sync();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), ua::StatusCode{Status::BadUserAccessDenied});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "ResendDataMethodFailed");
  EXPECT_EQ(result.shared_detail()->source, "client.tier1.subscription.resend_data");
}

// A live Publish DataChange is delivered to the callback as a decoded DataChangeEvent (node/attr pre-filled
// from the clientHandle table; the user never sees the wire handle).
TEST_F(SubscriptionHandleTest, MonitorDeliversDecodedDataChangeEvent)
{
  auto subscription = make_subscription();
  mSession->publish.set_hold(true);  // control the pump

  std::atomic<std::int32_t> deliveredValue{-1};
  std::atomic<std::uint32_t> deliveredItemId{0};
  ua::NodeId deliveredNode;
  std::mutex nodeMutex;

  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};
  const auto result = subscription.try_monitor_sync(request,
    [&](DataChangeEvent event)
    {
      if (auto asInt = event.value.value().try_as<std::int32_t>())
      {
        {
          std::lock_guard<std::mutex> lock(nodeMutex);
          deliveredNode = event.nodeId;
        }
        deliveredItemId.store(event.itemId);
        deliveredValue.store(*asInt);
      }
    });
  ASSERT_TRUE(result.is_good());
  const std::uint32_t clientHandle = result.value().client_handle();

  wait_until([&] { return mSession->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  mSession->publish.fire_next(
    Result<ua::PublishResponse>{make_publish_datachange(42, 1, clientHandle, 1234)});

  wait_until([&] { return deliveredValue.load() == 1234; }, "the DataChange to be delivered");
  EXPECT_EQ(deliveredItemId.load(), clientHandle);
  {
    std::lock_guard<std::mutex> lock(nodeMutex);
    EXPECT_EQ(deliveredNode, (ua::NodeId{2, 7})) << "the event carries the pre-decoded node";
  }
}

// @verifies CL-MI-030
// A structured Publish value that the wire decoder preserved as UnknownStructure must pass through the
// Connection's TypeResolver before the public Subscription callback fires.
// @relation(CL-MI-030, scope=function)
TEST_F(SubscriptionHandleTest, MonitorReifiesRegisteredStructuredNotification)
{
  register_argument_type();
  auto subscription = make_subscription();
  mSession->publish.set_hold(true);

  std::atomic<bool> deliveredTyped{false};
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 8};
  const auto monitored = subscription.try_monitor_sync(request,
    [&](DataChangeEvent event)
    {
      deliveredTyped.store(
        event.value.value().is_structure() &&
        dynamic_cast<const ua::Argument*>(&event.value.value().as<ua::Structure>()) != nullptr);
    });
  ASSERT_TRUE(monitored.is_good());

  wait_until([&] { return mSession->publish.pending_count() >= 1; }, "the pump to issue a Publish");
  mSession->publish.fire_next(Result<ua::PublishResponse>{
    make_publish_datachange(42, 1, monitored.value().client_handle(), make_argument_opaque_variant())});

  wait_until([&] { return deliveredTyped.load(); }, "the structured notification to be reified");
  EXPECT_TRUE(deliveredTyped.load());
}

// @verifies CL-MI-030
// An unresolvable ExtensionObject is never dropped: the callback receives the same opaque encoding/body and
// one source-tagged advisory. Repeating the encoding is coalesced by the bounded resolver gate.
// @relation(CL-MI-030, scope=function)
TEST_F(SubscriptionHandleTest, MonitorDeliversUnknownStructureAndCoalescesAdvisory)
{
  auto connection = make_connection();
  auto observer = std::make_shared<CapturingAdvisoryObserver>();
  connection.set_connection_observer(observer);
  auto subscription = connection.subscriptions().create_sync(SubscriptionConfig{500.0});
  mSession->publish.set_hold(true);

  const ua::NodeId encodingId{9, 9001U};
  const ua::ByteString body{0xCA, 0xFE};
  std::atomic<std::size_t> deliveredOpaque{0};
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 9};
  const auto monitored = subscription.try_monitor_sync(request,
    [&](DataChangeEvent event)
    {
      const auto* unknown = event.value.value().try_as<ua::UnknownStructure>();
      if (unknown != nullptr && unknown->encoding_id() == encodingId && unknown->encoded_data() == body)
      {
        deliveredOpaque.fetch_add(1);
      }
    });
  ASSERT_TRUE(monitored.is_good());

  wait_until([&] { return mSession->publish.pending_count() >= 1; }, "the first Publish request");
  mSession->publish.fire_next(Result<ua::PublishResponse>{make_publish_datachange(42,
    1,
    monitored.value().client_handle(),
    ua::Variant{
      ua::UnknownStructure{encodingId, ua::UnknownStructure::BodyEncoding::Binary, ua::ByteString{body}}})});

  wait_until([&] { return deliveredOpaque.load() == 1U; }, "the first opaque notification");
  wait_until([&] { return observer->count() == 1U; }, "the unresolved-type advisory");
  ASSERT_EQ(observer->count(), 1U);
  const auto detail = observer->last_detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->code, "MonitoredItemStructuredValueUnresolved");
  EXPECT_EQ(detail->source, "client.tier1.monitor.structured_value_unresolved");

  wait_until([&] { return mSession->publish.pending_count() >= 1; }, "the second Publish request");
  mSession->publish.fire_next(Result<ua::PublishResponse>{make_publish_datachange(42,
    2,
    monitored.value().client_handle(),
    ua::Variant{
      ua::UnknownStructure{encodingId, ua::UnknownStructure::BodyEncoding::Binary, ua::ByteString{body}}})});

  wait_until([&] { return deliveredOpaque.load() == 2U; }, "the repeated opaque notification");
  std::this_thread::sleep_for(20ms);
  EXPECT_EQ(observer->count(), 1U) << "the same encoding's advisory must be coalesced";
}

// --- MonitoredItem self-action delete routes through the real owner to the tier-0 session ---

TEST_F(SubscriptionHandleTest, MonitoredItemDeleteReachesTierZeroThroughOwner)
{
  auto subscription = make_subscription();
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};
  auto monitored = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
  ASSERT_TRUE(monitored.is_good());
  MonitoredItem item = monitored.value();

  const auto deleteResult = item.try_delete_sync();
  EXPECT_TRUE(deleteResult.is_good());
  EXPECT_EQ(mSession->deleteMonitoredItems.call_count(), 1u)
    << "the self-acting delete routes through the connection-lifetime owner to the tier-0 session";

  // After a successful delete the routing is gone: a second self-action misses -> Bad_SubscriptionIdInvalid.
  const auto secondDelete = item.try_delete_sync();
  EXPECT_EQ(secondDelete.status_code().value(), ua::StatusCode{Status::BadSubscriptionIdInvalid}.value());
}

// --- Subscription lifecycle ---

TEST_F(SubscriptionHandleTest, ModifyReachesTierZero)
{
  auto subscription = make_subscription();
  ua::client::SubscriptionModifyConfig config;
  config.publishingIntervalMs = 250.0;
  EXPECT_TRUE(subscription.try_modify_sync(config).is_good());
  EXPECT_EQ(mSession->modifySubscription.call_count(), 1u);
}

// CL-SUB-011: after a Good ModifySubscription the handle's publishing_interval() exposes the server-REVISED
// interval from the response, not the stale create-time (480) or the requested (250) value. RED before the
// mutable revised-interval snapshot: modify_async completed without recording revisedPublishingInterval.
// @verifies CL-SUB-011
// @relation(CL-SUB-011, scope=function)
TEST_F(SubscriptionHandleTest, ModifyUpdatesRevisedPublishingInterval)
{
  auto subscription = make_subscription();
  ASSERT_EQ(subscription.publishing_interval(), 480.0) << "the create-time server-revised interval";

  ua::ModifySubscriptionResponse response;
  response.revised_publishing_interval() = 300.0;  // the server revises the requested 250 -> 300
  mSession->modifySubscription.set_result(Result<ua::ModifySubscriptionResponse>{std::move(response)});

  ua::client::SubscriptionModifyConfig config;
  config.publishingIntervalMs = 250.0;
  ASSERT_TRUE(subscription.try_modify_sync(config).is_good());

  EXPECT_EQ(subscription.publishing_interval(), 300.0)
    << "a Good modify updates the handle to the server-revised interval (CL-SUB-011)";
}

// CL-SUB-011: a FAILED modify must NOT update the handle's publishing_interval() snapshot (the update is
// gated on a Good outcome, mirroring the publishing-enabled flag guard). @verifies CL-SUB-011
TEST_F(SubscriptionHandleTest, FailedModifyKeepsPublishingInterval)
{
  auto subscription = make_subscription();
  ASSERT_EQ(subscription.publishing_interval(), 480.0);

  ua::ModifySubscriptionResponse response;
  response.response_header().service_result() = ua::StatusCode{Status::BadTooManyOperations};
  response.revised_publishing_interval() = 300.0;  // present but must be ignored on a failed modify
  mSession->modifySubscription.set_result(Result<ua::ModifySubscriptionResponse>{std::move(response)});

  ua::client::SubscriptionModifyConfig config;
  config.publishingIntervalMs = 250.0;
  ASSERT_TRUE(subscription.try_modify_sync(config).is_bad());

  EXPECT_EQ(subscription.publishing_interval(), 480.0)
    << "a failed modify must not flip the handle's interval snapshot";
}

TEST_F(SubscriptionHandleTest, SetPublishingModeUpdatesFlag)
{
  auto subscription = make_subscription();
  ASSERT_TRUE(subscription.is_publishing_enabled());
  EXPECT_TRUE(subscription.try_set_publishing_mode_sync(false).is_good());
  EXPECT_EQ(mSession->setPublishingMode.call_count(), 1u);
  EXPECT_FALSE(subscription.is_publishing_enabled()) << "the handle snapshot tracks the applied mode";
}

TEST_F(SubscriptionHandleTest, CloseReachesTierZero)
{
  auto subscription = make_subscription();
  EXPECT_TRUE(subscription.try_close_sync().is_good());
  EXPECT_EQ(mSession->deleteSubscriptions.call_count(), 1u);
}

// A SetPublishingMode whose service result is Good but whose per-item results[0] is Bad_SubscriptionIdInvalid
// must surface the bad per-item status to the tier-1 caller (flatten_status_result collapses results[0]) AND
// must NOT flip the handle's publishing-enabled snapshot (the flag update is gated on a Good outcome). This
// pins the TIER-1 facade decomposition + state-guard - distinct from the session-service forwarder coverage
// (SessionSubscriptionServicesSetPublishingMode, results[] preserved verbatim) and the ConnectionImpl wire-op
// coverage (SetPublishingModeHonoursPerItemResultWhenServiceGood, raw results[0] surfaced).
// @verifies CL-SUB-014
// @relation(CL-SUB-014, scope=function)
TEST_F(SubscriptionHandleTest, SetPublishingModePerItemBadSurfacedKeepsFlag)
{
  auto subscription = make_subscription();
  ASSERT_TRUE(subscription.is_publishing_enabled());

  ua::SetPublishingModeResponse response;  // service result defaults Good
  response.results().push_back(ua::StatusCode{Status::BadSubscriptionIdInvalid});
  mSession->setPublishingMode.set_result(Result<ua::SetPublishingModeResponse>{std::move(response)});

  const auto result = subscription.try_set_publishing_mode_sync(false);
  ASSERT_TRUE(result.is_bad()) << "a per-item Bad must dominate the Good service result";
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadSubscriptionIdInvalid}.value())
    << "the exact per-item status must reach the tier-1 caller";
  EXPECT_TRUE(subscription.is_publishing_enabled())
    << "a failed set_publishing_mode must NOT flip the handle's mode snapshot";
}

// The replay record a session-CHANGED recreate would replay is the pipeline's retained publishing interval.
// On a Good modify the record now tracks the MODIFIED value (CL-SUB-012 built: modify_subscription_async
// wraps its completion to update_publishing_interval_async), so a recreate replays the modified interval, not
// the stale create-time one. pipeline_recovery_descriptors hops the pipeline strand, draining the queued
// update.
// @verifies CL-SUB-012
// @relation(CL-SUB-012, scope=function)
TEST_F(SubscriptionHandleTest, ModifyUpdatesReplayRecordInterval)
{
  auto subscription = make_subscription();  // requested 500 -> registered in the replay record at 500
  ua::client::SubscriptionModifyConfig config;
  config.publishingIntervalMs = 250.0;
  ASSERT_TRUE(subscription.try_modify_sync(config).is_good());

  const auto descriptors = TA::pipeline_recovery_descriptors(*mConnection);
  ASSERT_EQ(descriptors.size(), 1u) << "the modified subscription remains a recovery candidate";
  EXPECT_EQ(descriptors.front().subscriptionId, 42u);
  EXPECT_DOUBLE_EQ(descriptors.front().publishingInterval, 250.0)
    << "a Good modify updates the replay record so a recreate replays the modified interval (CL-SUB-012)";
}

// --- A Subscription's or MonitoredItem's answer code reaches the caller; local state follows its data ---
//
// The handle's snapshot (publishing interval, publishing mode, a MonitoredItem's revised values, mode and
// registration) follows every answer that holds data and is not Bad: a Good one, a Good subcode included, or
// an Uncertain one, whose data the caller receives with the code. An Uncertain answer without a response
// changes nothing. The code itself, Good subcode or Uncertain, reaches the caller in every case.

/// A response with ServiceResult @p serviceResult and the single per-item code @p itemCode.
template<class Response>
Response make_status_response(ua::StatusCode serviceResult, ua::StatusCode itemCode)
{
  Response response;
  response.response_header().service_result() = std::move(serviceResult);
  response.results().push_back(std::move(itemCode));
  return response;
}

/// A ModifyMonitoredItems response whose single item answers @p itemCode with the given revised values.
ua::ModifyMonitoredItemsResponse make_item_modify_response(
  ua::StatusCode itemCode, double revisedSamplingInterval, std::uint32_t revisedQueueSize)
{
  ua::MonitoredItemModifyResult item;
  item.status_code() = std::move(itemCode);
  item.revised_sampling_interval() = revisedSamplingInterval;
  item.revised_queue_size() = revisedQueueSize;
  ua::ModifyMonitoredItemsResponse response;
  response.results().push_back(std::move(item));
  return response;
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, ModifyKeepsAGoodSubcodeAndRecordsTheRevisedInterval)
{
  auto subscription = make_subscription();
  ua::ModifySubscriptionResponse response;
  response.response_header().service_result() = ua::StatusCode{Status::GoodOverload};
  response.revised_publishing_interval() = 300.0;
  mSession->modifySubscription.set_result(Result<ua::ModifySubscriptionResponse>{std::move(response)});

  ua::client::SubscriptionModifyConfig config;
  config.publishingIntervalMs = 250.0;
  const auto result = subscription.try_modify_sync(config);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::GoodOverload}.value());
  EXPECT_EQ(subscription.publishing_interval(), 300.0) << "a Good subcode is a Good answer";
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, ModifyKeepsAnUncertainServiceResultAndRecordsTheRevisedInterval)
{
  auto subscription = make_subscription();  // requested 500, revised 480
  ua::ModifySubscriptionResponse response;
  response.response_header().service_result() = ua::StatusCode{Status::UncertainLastUsableValue};
  response.revised_publishing_interval() = 300.0;
  mSession->modifySubscription.set_result(Result<ua::ModifySubscriptionResponse>{std::move(response)});

  ua::client::SubscriptionModifyConfig config;
  config.publishingIntervalMs = 250.0;
  const auto result = subscription.try_modify_sync(config);

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(subscription.publishing_interval(), 300.0)
    << "the revised interval the caller receives with the Uncertain code is recorded";
  const auto descriptors = TA::pipeline_recovery_descriptors(*mConnection);
  ASSERT_EQ(descriptors.size(), 1u);
  EXPECT_DOUBLE_EQ(descriptors.front().publishingInterval, 250.0)
    << "a recreate replays the modified interval, as the handle reports it";
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, SetPublishingModeKeepsAGoodSubcodeAndAppliesTheMode)
{
  auto subscription = make_subscription();
  mSession->setPublishingMode.set_result(
    Result<ua::SetPublishingModeResponse>{make_status_response<ua::SetPublishingModeResponse>(
      ua::StatusCode{Status::GoodOverload}, ua::StatusCode{Status::Good})});

  const auto result = subscription.try_set_publishing_mode_sync(false);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::GoodOverload}.value());
  EXPECT_FALSE(subscription.is_publishing_enabled()) << "a Good subcode is a Good answer";
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, SetPublishingModeKeepsAnUncertainItemCodeAndAppliesTheMode)
{
  auto subscription = make_subscription();
  mSession->setPublishingMode.set_result(
    Result<ua::SetPublishingModeResponse>{make_status_response<ua::SetPublishingModeResponse>(
      ua::StatusCode{Status::Good}, ua::StatusCode{Status::UncertainLastUsableValue})});

  const auto result = subscription.try_set_publishing_mode_sync(false);

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_FALSE(subscription.is_publishing_enabled())
    << "an Uncertain answer with its result applies the mode";
}

// An Uncertain answer without a response holds no Subscription result, so the mode is not applied.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, SetPublishingModeAnsweredUncertainWithoutAResponseKeepsTheMode)
{
  auto subscription = make_subscription();
  mSession->setPublishingMode.set_result(
    Result<ua::SetPublishingModeResponse>{ua::StatusCode{Status::UncertainLastUsableValue}});

  const auto result = subscription.try_set_publishing_mode_sync(false);

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_TRUE(subscription.is_publishing_enabled()) << "an answer without a response changes nothing";
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, CloseKeepsAnUncertainServiceResult)
{
  auto subscription = make_subscription();
  mSession->deleteSubscriptions.set_result(
    Result<ua::DeleteSubscriptionsResponse>{make_status_response<ua::DeleteSubscriptionsResponse>(
      ua::StatusCode{Status::UncertainLastUsableValue}, ua::StatusCode{Status::Good})});

  const auto result = subscription.try_close_sync();

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, GetMonitoredItemsKeepsAGoodSubcodeServiceResultWithTheHandles)
{
  auto response = make_get_monitored_items_response(ua::StatusCode{Status::Good},
    ua::Variant{ua::Array<std::uint32_t>{101}},
    ua::Variant{ua::Array<std::uint32_t>{201}});
  response.response_header().service_result() = ua::StatusCode{Status::GoodOverload};
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});
  auto subscription = make_subscription();

  const auto result = subscription.try_get_monitored_items_sync();

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::GoodOverload}.value());
  EXPECT_EQ(result.value().serverHandles, (std::vector<ua::IntegerId>{101}));
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, GetMonitoredItemsHoldsTheHandlesWithAnUncertainMethodCode)
{
  mSession->call.set_result(Result<ua::CallResponse>{
    make_get_monitored_items_response(ua::StatusCode{Status::UncertainLastUsableValue},
      ua::Variant{ua::Array<std::uint32_t>{101}},
      ua::Variant{ua::Array<std::uint32_t>{201}})});
  auto subscription = make_subscription();

  const auto result = subscription.try_get_monitored_items_sync();

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_NO_THROW({ EXPECT_EQ(result.value().clientHandles, (std::vector<ua::IntegerId>{201})); })
    << "the handles are held with the Uncertain code";
  EXPECT_THROW((void)subscription.get_monitored_items_sync(), ua::UaException)
    << "the throwing form gives only a Good answer's value";
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, ResendDataKeepsAnUncertainMethodCode)
{
  mSession->call.set_result(Result<ua::CallResponse>{
    make_get_monitored_items_response(ua::StatusCode{Status::UncertainLastUsableValue})});
  auto subscription = make_subscription();

  const auto result = subscription.try_resend_data_sync();

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, ResendDataKeepsAGoodSubcodeServiceResult)
{
  auto response = make_get_monitored_items_response(ua::StatusCode{Status::Good});
  response.response_header().service_result() = ua::StatusCode{Status::GoodOverload};
  mSession->call.set_result(Result<ua::CallResponse>{std::move(response)});
  auto subscription = make_subscription();

  const auto result = subscription.try_resend_data_sync();

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::GoodOverload}.value());
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, MonitoredItemDeleteKeepsTheItemsGoodSubcode)
{
  auto subscription = make_subscription();
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};
  auto monitored = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
  ASSERT_TRUE(monitored.is_good());
  mSession->deleteMonitoredItems.set_result(
    Result<ua::DeleteMonitoredItemsResponse>{make_status_response<ua::DeleteMonitoredItemsResponse>(
      ua::StatusCode{Status::Good}, ua::StatusCode{Status::GoodOverload})});

  const auto result = monitored.value().try_delete_sync();

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::GoodOverload}.value());
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, MonitoredItemModifyKeepsAGoodSubcodeAndRecordsTheRevisedValues)
{
  auto subscription = make_subscription();
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};
  auto monitored = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
  ASSERT_TRUE(monitored.is_good());
  MonitoredItem item = monitored.value();
  mSession->modifyMonitoredItems.set_result(Result<ua::ModifyMonitoredItemsResponse>{
    make_item_modify_response(ua::StatusCode{Status::GoodOverload}, 250.0, 7)});

  MonitorRequest modify;
  modify.nodeId = ua::NodeId{2, 7};
  modify.samplingIntervalMs = 200.0;
  const auto result = item.try_modify_sync(modify);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::GoodOverload}.value());
  EXPECT_EQ(item.revised_sampling_interval(), 250.0) << "a Good subcode is a Good answer";
  EXPECT_EQ(item.revised_queue_size(), 7u);
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, MonitoredItemModifyKeepsAnUncertainCodeAndRecordsTheRevisedValues)
{
  auto subscription = make_subscription();
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};
  auto monitored = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
  ASSERT_TRUE(monitored.is_good());
  MonitoredItem item = monitored.value();
  mSession->modifyMonitoredItems.set_result(Result<ua::ModifyMonitoredItemsResponse>{
    make_item_modify_response(ua::StatusCode{Status::UncertainLastUsableValue}, 250.0, 7)});

  MonitorRequest modify;
  modify.nodeId = ua::NodeId{2, 7};
  modify.samplingIntervalMs = 200.0;
  const auto result = item.try_modify_sync(modify);

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(item.revised_sampling_interval(), 250.0)
    << "the revised values the caller receives with the Uncertain code are recorded";
  EXPECT_EQ(item.revised_queue_size(), 7u);
}

// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, MonitoredItemSetModeKeepsAnUncertainCodeAndAppliesTheMode)
{
  auto subscription = make_subscription();
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};
  auto monitored = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
  ASSERT_TRUE(monitored.is_good());
  MonitoredItem item = monitored.value();
  ASSERT_EQ(item.mode(), ua::MonitoringMode::Reporting);
  mSession->setMonitoringMode.set_result(
    Result<ua::SetMonitoringModeResponse>{make_status_response<ua::SetMonitoringModeResponse>(
      ua::StatusCode{Status::Good}, ua::StatusCode{Status::UncertainLastUsableValue})});

  const auto result = item.try_set_mode_sync(ua::MonitoringMode::Disabled);

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(item.mode(), ua::MonitoringMode::Disabled)
    << "an Uncertain answer with its result applies the mode";
}

// An Uncertain DeleteMonitoredItems answer with the item's result deletes the item locally as a Good one
// does: a second delete fails locally (the item is no longer routed) and sends nothing.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, MonitoredItemDeleteAnsweredUncertainUnregistersTheItem)
{
  auto subscription = make_subscription();
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};
  auto monitored = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
  ASSERT_TRUE(monitored.is_good());
  MonitoredItem item = monitored.value();
  mSession->deleteMonitoredItems.set_result(
    Result<ua::DeleteMonitoredItemsResponse>{make_status_response<ua::DeleteMonitoredItemsResponse>(
      ua::StatusCode{Status::Good}, ua::StatusCode{Status::UncertainLastUsableValue})});

  const auto result = item.try_delete_sync();

  EXPECT_TRUE(result.is_uncertain());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::UncertainLastUsableValue}.value());
  const auto again = item.try_delete_sync();
  EXPECT_EQ(again.status_code().as_status(), Status::BadSubscriptionIdInvalid)
    << "the deleted item is no longer routed";
  EXPECT_EQ(mSession->deleteMonitoredItems.call_count(), 1u) << "the second delete is not sent";
}

// An Uncertain DeleteMonitoredItems answer without a response holds no item result: the item stays routed, so
// a second delete is sent.
// @relation(AC-CL-STATUS-ROUTING-01-A-MONITORING-OR-SUBSCRIPTION-CODE-REACHES-THE-APPLICATION, scope=function)
TEST_F(SubscriptionHandleTest, MonitoredItemDeleteAnsweredUncertainWithoutAResponseKeepsTheItem)
{
  auto subscription = make_subscription();
  MonitorRequest request;
  request.nodeId = ua::NodeId{2, 7};
  auto monitored = subscription.try_monitor_sync(request, [](DataChangeEvent) {});
  ASSERT_TRUE(monitored.is_good());
  MonitoredItem item = monitored.value();
  mSession->deleteMonitoredItems.set_result(
    Result<ua::DeleteMonitoredItemsResponse>{ua::StatusCode{Status::UncertainLastUsableValue}});

  const auto result = item.try_delete_sync();

  EXPECT_TRUE(result.is_uncertain());
  mSession->deleteMonitoredItems.set_result(
    Result<ua::DeleteMonitoredItemsResponse>{make_status_response<ua::DeleteMonitoredItemsResponse>()});
  EXPECT_TRUE(item.try_delete_sync().is_good()) << "the item is still routed, so the second delete is sent";
  EXPECT_EQ(mSession->deleteMonitoredItems.call_count(), 2u);
}

// --- set_triggering local validation ---

TEST_F(SubscriptionHandleTest, SetTriggeringUnresolvedHandleFailsLocally)
{
  auto subscription = make_subscription();
  MonitoredItem unregisteredTrigger;  // empty handle -> no live routing
  const auto result = subscription.try_set_triggering_sync(unregisteredTrigger, {}, {});
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().value(), ua::StatusCode{Status::BadMonitoredItemIdInvalid}.value());
  EXPECT_EQ(mSession->setTriggering.call_count(), 0u) << "an unresolved handle never reaches the wire";
}

// --- DataChangeMonitoredItemOwner: the J19 gone-vs-miss split (section 7.4) exercised on the REAL owner ---

// The back-lock to the owning Connection failing is a fully-closed Connection (the owner only dies with its
// ConnectionImpl) -> Bad_ConnectionClosed, distinct from a registry-lookup miss (J19). Built with an already-
// expired weak Connection so the routing lookup HITS but the connection lock FAILS.
TEST(DataChangeMonitoredItemOwner, ConnectionGoneCompletesBadConnectionClosed)
{
  auto owner = DataChangeMonitoredItemOwner::create(std::weak_ptr<ConnectionImpl>{});  // no live Connection
  owner->register_item(/*clientHandle=*/5, /*subscriptionId=*/77, /*monitoredItemId=*/100);

  VoidResult deleteResult{};
  owner->mi_delete_async(5, [&deleteResult](VoidResult result) { deleteResult = result; });
  ASSERT_TRUE(deleteResult.is_bad());
  EXPECT_EQ(deleteResult.status_code().value(), ua::StatusCode{Status::BadConnectionClosed}.value())
    << "a failed back-lock to the Connection is Bad_ConnectionClosed, not Bad_SubscriptionIdInvalid (J19)";
  ASSERT_NE(deleteResult.shared_detail(), nullptr);
  EXPECT_EQ(deleteResult.shared_detail()->source, "client.tier1.data_change_owner.connection_gone");
}

// A registry-lookup MISS on a LIVE owner (the item was never registered / already deleted) -> the server item
// is gone -> Bad_SubscriptionIdInvalid, distinct from the Connection being closed (J19). The live owner's
// back-lock succeeds, so only the missing routing drives the status; no wire op is issued.
TEST_F(SubscriptionHandleTest, OwnerLookupMissCompletesBadSubscriptionIdInvalid)
{
  auto owner = DataChangeMonitoredItemOwner::create(mConnection);  // LIVE Connection back-reference
  VoidResult deleteResult{};
  owner->mi_delete_async(
    /*unregistered clientHandle=*/999, [&deleteResult](VoidResult result) { deleteResult = result; });
  ASSERT_TRUE(deleteResult.is_bad());
  EXPECT_EQ(deleteResult.status_code().value(), ua::StatusCode{Status::BadSubscriptionIdInvalid}.value())
    << "a live-owner registry miss is Bad_SubscriptionIdInvalid, not Bad_ConnectionClosed (J19)";
  ASSERT_NE(deleteResult.shared_detail(), nullptr);
  EXPECT_EQ(deleteResult.shared_detail()->source, "client.tier1.data_change_owner.lookup_miss");
  EXPECT_EQ(mSession->deleteMonitoredItems.call_count(), 0u) << "a lookup miss never reaches the wire";
}

// WARNING 3 (owner-level): unregister_subscription drops EVERY routing entry owned by the given subscription
// in one pass, and leaves entries owned by OTHER subscriptions intact.
TEST(DataChangeMonitoredItemOwner, UnregisterSubscriptionPurgesOnlyMatchingRouting)
{
  auto owner = DataChangeMonitoredItemOwner::create(std::weak_ptr<ConnectionImpl>{});
  owner->register_item(/*clientHandle=*/1, /*subscriptionId=*/77, /*monitoredItemId=*/100);
  owner->register_item(/*clientHandle=*/2, /*subscriptionId=*/77, /*monitoredItemId=*/101);
  owner->register_item(/*clientHandle=*/3, /*subscriptionId=*/88, /*monitoredItemId=*/200);

  owner->unregister_subscription(77);

  EXPECT_FALSE(owner->subscription_of(1).has_value()) << "sub 77's item 1 routing must be purged";
  EXPECT_FALSE(owner->subscription_of(2).has_value()) << "sub 77's item 2 routing must be purged";
  ASSERT_EQ(owner->subscription_of(3), std::optional<std::uint32_t>{88})
    << "an unrelated subscription's routing must survive the purge";
  EXPECT_EQ(owner->server_item_id(3), std::optional<std::uint32_t>{200});
}

// WARNING 3 (owner re-key batch): rekey_items repoints each preserved clientHandle to its NEW
// {subscriptionId, monitoredItemId} in one batch (the session-CHANGED recreate commit).
TEST(DataChangeMonitoredItemOwner, RekeyItemsRepointsRoutingBatch)
{
  auto owner = DataChangeMonitoredItemOwner::create(std::weak_ptr<ConnectionImpl>{});
  owner->register_item(/*clientHandle=*/1, /*subscriptionId=*/77, /*monitoredItemId=*/100);
  owner->register_item(/*clientHandle=*/2, /*subscriptionId=*/77, /*monitoredItemId=*/101);

  owner->rekey_items({DataChangeMonitoredItemOwner::ItemRekey{1, 88, 900},
    DataChangeMonitoredItemOwner::ItemRekey{2, 88, 901}});

  EXPECT_EQ(owner->subscription_of(1), std::optional<std::uint32_t>{88});
  EXPECT_EQ(owner->server_item_id(1), std::optional<std::uint32_t>{900});
  EXPECT_EQ(owner->subscription_of(2), std::optional<std::uint32_t>{88});
  EXPECT_EQ(owner->server_item_id(2), std::optional<std::uint32_t>{901});
}

// --- Notification assembly: same-type grouping across a mixed data + event cycle ---

// Part 4 section 7.26: notifications of the same type are grouped into ONE NotificationData element, and a
// Subscription holding both event and data MonitoredItems produces no more than two elements. A plausible
// assembler appends one element per drained notification, or opens a fresh element whenever the item type
// changes while walking its item map; either delivers every notification and passes a notification-count
// check, while multiplying the per-message encoding overhead by the notification count. The two data items
// and the two event items must therefore land in exactly two elements - one DataChangeNotification carrying
// both data notifications, one EventNotificationList carrying both events.
// @verifies AC-SVR-SUB-GEN-091-NOTIFICATION-GROUPING
TEST(SubscriptionNotificationAssembly, DataChangesAndEventsAreGroupedIntoOneElementPerType)
{
  // Declared first so it is destroyed last: the subscription's publishing timer is cancelled by
  // ~Subscription before the runtime drains.
  ua::test_helpers::AsyncTestRuntime runtime;

  auto subscription = ua::server::Subscription::create(/*subscriptionId=*/
    7,
    /*publishingInterval=*/5000.0,
    /*lifetimeCount=*/100,
    /*maxKeepAliveCount=*/3,
    /*maxNotificationsPerPublish=*/0,
    /*publishingEnabled=*/true,
    /*priority=*/0,
    runtime.executor(),
    [](ua::IntegerId) {},
    [](ua::IntegerId) {});
  ASSERT_NE(subscription, nullptr);

  ua::server::SubscriptionTestAccess::on_strand(*subscription,
    [](auto& guard)
    {
      // Two data-change items, each with one queued notification.
      auto dataOne = std::make_unique<ua::server::MonitoredItem>();
      dataOne->monitoringMode = ua::MonitoringMode::Reporting;
      dataOne->clientHandle = 10;
      dataOne->queueSize = 10;
      dataOne->enqueue_initial(ua::DataValue{ua::Variant{100}});
      guard.add_monitored_item(std::move(dataOne));

      auto dataTwo = std::make_unique<ua::server::MonitoredItem>();
      dataTwo->monitoringMode = ua::MonitoringMode::Reporting;
      dataTwo->clientHandle = 20;
      dataTwo->queueSize = 10;
      dataTwo->enqueue_initial(ua::DataValue{ua::Variant{200}});
      guard.add_monitored_item(std::move(dataTwo));

      // Two event items, each with one queued event, in the same cycle.
      auto eventOne = std::make_unique<ua::server::MonitoredItem>();
      eventOne->monitoringMode = ua::MonitoringMode::Reporting;
      eventOne->clientHandle = 30;
      eventOne->queueSize = 10;
      eventOne->isEventItem = true;
      ua::EventFieldList firstFields;
      firstFields.client_handle() = 30;
      firstFields.event_fields().push_back(ua::Variant{std::uint16_t{500}});
      eventOne->enqueue_event(std::move(firstFields));
      guard.add_monitored_item(std::move(eventOne));

      auto eventTwo = std::make_unique<ua::server::MonitoredItem>();
      eventTwo->monitoringMode = ua::MonitoringMode::Reporting;
      eventTwo->clientHandle = 40;
      eventTwo->queueSize = 10;
      eventTwo->isEventItem = true;
      ua::EventFieldList secondFields;
      secondFields.client_handle() = 40;
      secondFields.event_fields().push_back(ua::Variant{std::uint16_t{700}});
      eventTwo->enqueue_event(std::move(secondFields));
      guard.add_monitored_item(std::move(eventTwo));
    });

  auto results = ua::server::SubscriptionTestAccess::on_strand(
    *subscription, [](auto& guard) { return guard.fulfill_publish(1); });

  ASSERT_EQ(results.size(), 1u) << "one Publish is fulfilled, carrying the whole cycle";
  auto& message = results[0].message;
  ASSERT_EQ(message.notification_data().size(), 2u)
    << "a cycle mixing data and events yields exactly two NotificationData elements, not one per "
       "notification";

  auto* dataChanges = dynamic_cast<ua::DataChangeNotification*>(message.notification_data()[0].get());
  ASSERT_NE(dataChanges, nullptr) << "the data changes occupy their own NotificationData element";
  ASSERT_EQ(dataChanges->monitored_items().size(), 2u)
    << "both data notifications are grouped into that one element";
  const auto firstDataHandle = dataChanges->monitored_items()[0].client_handle();
  const auto secondDataHandle = dataChanges->monitored_items()[1].client_handle();
  EXPECT_TRUE((firstDataHandle == 10u && secondDataHandle == 20u) ||
              (firstDataHandle == 20u && secondDataHandle == 10u))
    << "the grouped element carries both data items, not one item's notifications twice";

  auto* events = dynamic_cast<ua::EventNotificationList*>(message.notification_data()[1].get());
  ASSERT_NE(events, nullptr) << "the events occupy a separate NotificationData element, not the data one";
  ASSERT_EQ(events->events().size(), 2u) << "both events are grouped into that one element";
  const auto firstEventHandle = events->events()[0].client_handle();
  const auto secondEventHandle = events->events()[1].client_handle();
  EXPECT_TRUE((firstEventHandle == 30u && secondEventHandle == 40u) ||
              (firstEventHandle == 40u && secondEventHandle == 30u))
    << "the grouped element carries both event items";
}

}  // namespace
