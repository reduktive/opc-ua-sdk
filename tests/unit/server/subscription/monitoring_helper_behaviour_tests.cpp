// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the in-memory namespace's monitored items behave across a modify and across a Node deleted and added
// again, as a client sees them (COMP-SVR-NAMESPACE-MONITORING-HELPER-03,
// COMP-SVR-NAMESPACE-MONITORING-INVALIDATION-01).
//
// The Subscription is driven as the pipeline drives it: CreateMonitoredItems and ModifyMonitoredItems through
// their asynchronous entries, the Variable's Value written through its accessor, and the notifications taken
// by fulfill_publish.

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "test_utilities.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_node_accessor.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using STA = SubscriptionTestAccess;

namespace
{

class MonitoringHelperBehaviour : public ::testing::Test
{
protected:
  struct Reported
  {
    uint32_t handle;
    Variant value;
    StatusCode status;
  };

  struct Created
  {
    StatusCode status;
    IntegerId monitoredItemId{0};
    Duration revisedSamplingInterval{-1};
  };

  struct Modified
  {
    StatusCode status;
    Duration revisedSamplingInterval{-1};
  };

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test:monitoring-helper-behaviour", mExecutor));
    mSecurityContext = std::make_shared<test_helpers::TestSessionSecurityContext>(*mAddressSpace);
    mCapabilities.minSupportedSampleRate = 0;
    mCapabilities.maxMonitoredItemsQueueSize = 1000u;
    mSubscription =
      Subscription::create(1, 1'000'000.0, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  }

  void TearDown() override
  {
    mSubscription.reset();
    mSecurityContext.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  /// An Int32 Variable in the in-memory namespace holding 0, readable and writable, whose
  /// MinimumSamplingInterval is @p minimumSamplingInterval.
  void create_variable(const NodeId& nodeId, Duration minimumSamplingInterval)
  {
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::Variable, {});
    ASSERT_TRUE(created.is_good()) << "the Variable could not be created: "
                                   << to_string(created.status_code());
    auto variable = created.value().as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    created.value().write_attribute_sync(
      AttributeId::MinimumSamplingInterval, Variant{minimumSamplingInterval});
    variable->write_value_sync(DataValue{Variant{int32_t{0}}});
  }

  /// Writes @p value to the Variable's Value through its accessor, as an internal write.
  void write_value(const NodeId& nodeId, int32_t value)
  {
    auto variable = mAddressSpace->find_node_sync(nodeId).as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    const auto written = variable->try_write_value_sync(DataValue{Variant{value}});
    ASSERT_TRUE(written.is_good()) << "the write of " << value
                                   << " was refused: " << to_string(written.status_code());
  }

  /// Creates an item with @p clientHandle on @p nodeId's Value, queue size 10.
  Created create_item(const NodeId& nodeId, uint32_t clientHandle, Duration samplingInterval)
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = nodeId;
    item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = samplingInterval;
    item.requested_parameters().queue_size() = 10;
    item.requested_parameters().discard_oldest() = true;

    CreateMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_create().push_back(std::move(item));
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemCreateResult>>>();
    auto future = promise->get_future();
    mSubscription->create_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      mSecurityContext,
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise](std::vector<MonitoredItemCreateResult> results) { promise->set_value(std::move(results)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the create did not answer";
      return {StatusCode{Status::BadTimeout}};
    }
    auto results = future.get();
    if (results.size() != 1u)
    {
      ADD_FAILURE() << "the create answered " << results.size() << " results for one item";
      return {StatusCode{Status::BadInternalError}};
    }
    return {results[0].status_code(), results[0].monitored_item_id(), results[0].revised_sampling_interval()};
  }

  /// Modifies the item @p monitoredItemId to @p samplingInterval, keeping @p clientHandle and queue size 10.
  Modified modify_item(IntegerId monitoredItemId, uint32_t clientHandle, Duration samplingInterval)
  {
    MonitoredItemModifyRequest item;
    item.monitored_item_id() = monitoredItemId;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = samplingInterval;
    item.requested_parameters().queue_size() = 10;
    item.requested_parameters().discard_oldest() = true;

    ModifyMonitoredItemsRequest request;
    request.subscription_id() = 1;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    request.items_to_modify().push_back(std::move(item));
    auto promise = std::make_shared<std::promise<std::vector<MonitoredItemModifyResult>>>();
    auto future = promise->get_future();
    mSubscription->modify_monitored_items_async(std::move(request),
      *mAddressSpace,
      mCapabilities,
      mSubscriptionLimits,
      [promise](std::vector<MonitoredItemModifyResult> results) { promise->set_value(std::move(results)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the modify did not answer";
      return {StatusCode{Status::BadTimeout}};
    }
    auto results = future.get();
    if (results.size() != 1u)
    {
      ADD_FAILURE() << "the modify answered " << results.size() << " results for one item";
      return {StatusCode{Status::BadInternalError}};
    }
    return {results[0].status_code(), results[0].revised_sampling_interval()};
  }

  /// Deletes the item @p monitoredItemId; returns its StatusCode.
  StatusCode delete_item(IntegerId monitoredItemId)
  {
    auto promise = std::make_shared<std::promise<std::vector<StatusCode>>>();
    auto future = promise->get_future();
    mSubscription->delete_monitored_items_async(std::vector<IntegerId>{monitoredItemId},
      *mAddressSpace,
      std::weak_ptr<EventBus>{},
      nullptr,
      [promise](std::vector<StatusCode> results) { promise->set_value(std::move(results)); });
    if (future.wait_for(5s) != std::future_status::ready)
    {
      ADD_FAILURE() << "the delete did not answer";
      return StatusCode{Status::BadTimeout};
    }
    auto results = future.get();
    if (results.size() != 1u)
    {
      ADD_FAILURE() << "the delete answered " << results.size() << " results for one item";
      return StatusCode{Status::BadInternalError};
    }
    return results[0];
  }

  /// Publishes, recording every notification, until @p done holds or @p timeout passes. Returns whether it
  /// held.
  bool publish_until(const std::function<bool()>& done, std::chrono::milliseconds timeout = 3s)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;)
    {
      publish_once();
      if (done())
        return true;
      if (std::chrono::steady_clock::now() >= deadline)
        return false;
      std::this_thread::sleep_for(5ms);
    }
  }

  /// Publishes for @p duration, recording every notification.
  void publish_for(std::chrono::milliseconds duration)
  {
    const auto deadline = std::chrono::steady_clock::now() + duration;
    while (std::chrono::steady_clock::now() < deadline)
    {
      publish_once();
      std::this_thread::sleep_for(5ms);
    }
  }

  void publish_once()
  {
    auto published = STA::on_strand(*mSubscription,
      [](auto& guard)
      {
        guard.set_publish_req_queued(true);
        return guard.fulfill_publish(1);
      });
    for (const auto& result : published)
    {
      for (const auto& data : result.message.notification_data())
      {
        const auto* change = dynamic_cast<const DataChangeNotification*>(data.get());
        if (change == nullptr)
          continue;
        for (const auto& notification : change->monitored_items())
        {
          mReported.push_back({notification.client_handle(),
            notification.value().value(),
            notification.value().status().value_or(StatusCode{Status::Good})});
        }
      }
    }
  }

  /// The notifications of the item with @p clientHandle so far.
  std::vector<Reported> reports_of(uint32_t clientHandle) const
  {
    std::vector<Reported> found;
    for (const auto& reported : mReported)
    {
      if (reported.handle == clientHandle)
        found.push_back(reported);
    }
    return found;
  }

  /// The number of notifications of the item with @p clientHandle so far.
  size_t report_count(uint32_t clientHandle) const
  {
    return reports_of(clientHandle).size();
  }

  /// The Good Int32 values the item with @p clientHandle reported from its @p from-th notification on, in
  /// order.
  std::vector<int32_t> good_values_of(uint32_t clientHandle, size_t from = 0) const
  {
    std::vector<int32_t> values;
    const auto reports = reports_of(clientHandle);
    for (size_t index = from; index < reports.size(); ++index)
    {
      if (reports[index].status.is_good() && reports[index].value.is_int32())
        values.push_back(reports[index].value.as<int32_t>());
    }
    return values;
  }

  /// How many notifications of the item with @p clientHandle carry @p status.
  size_t count_status(uint32_t clientHandle, StatusCode status) const
  {
    size_t count = 0;
    for (const auto& reported : reports_of(clientHandle))
    {
      if (reported.status == status)
        ++count;
    }
    return count;
  }

  std::string reports_text(uint32_t clientHandle) const
  {
    std::string text = "the item reported:";
    for (const auto& reported : reports_of(clientHandle))
      text += " " + to_string(reported.value) + " [" + to_string(reported.status) + "];";
    return text;
  }

  boost::asio::thread_pool mThreadPool{4};
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<test_helpers::TestSessionSecurityContext> mSecurityContext;
  std::shared_ptr<Subscription> mSubscription;
  ServerConfig::ServerCapabilities mCapabilities;
  ServerConfig::SubscriptionLimits mSubscriptionLimits;
  std::vector<Reported> mReported;
};

class MonitoringHelperModify : public MonitoringHelperBehaviour
{};

class MonitoringHelperDeletion : public MonitoringHelperBehaviour
{};

constexpr uint32_t handleX = 1;
constexpr uint32_t handleY = 2;

}  // namespace

// COMP-SVR-NAMESPACE-MONITORING-HELPER-03 rule 1: a modify of Y from interval 0 to 1000 changes Y's delivery
// and no other registration's. X, created first on the same Value, keeps reporting every change.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-03-A-MODIFY-LEAVES-THE-OTHER-REGISTRATIONS-ON-THE-NODE-AS-THEY-WERE, scope=function)
TEST_F(MonitoringHelperModify, AModifyLeavesTheOtherRegistrationsOnTheNodeAsTheyWere)
{
  const NodeId variable{1, 1000u};
  create_variable(variable, 0);
  const auto x = create_item(variable, handleX, 0);
  ASSERT_TRUE(x.status.is_good()) << "X was created with " << to_string(x.status);
  const auto y = create_item(variable, handleY, 0);
  ASSERT_TRUE(y.status.is_good()) << "Y was created with " << to_string(y.status);
  ASSERT_TRUE(publish_until([&] { return report_count(handleX) >= 1 && report_count(handleY) >= 1; }))
    << "the initial values were not delivered";
  const auto xBefore = report_count(handleX);
  const auto yBefore = report_count(handleY);

  const auto modified = modify_item(y.monitoredItemId, handleY, 1000);
  ASSERT_TRUE(modified.status.is_good()) << "Y's modify answered " << to_string(modified.status);

  for (const int32_t value : {1, 2, 3})
  {
    write_value(variable, value);
    std::this_thread::sleep_for(50ms);
  }
  publish_for(500ms);

  EXPECT_EQ(good_values_of(handleX, xBefore), (std::vector<int32_t>{1, 2, 3}))
    << "X: " << reports_text(handleX);
  EXPECT_LE(good_values_of(handleY, yBefore).size(), 1u) << "Y: " << reports_text(handleY);
}

// NR-47 rule 2 and Part 4 5.12.1.2: a Value item's revised interval is at least the Variable's
// MinimumSamplingInterval on a modify as on create, and an item sampled at 500 ms does not report each of
// three writes 20 ms apart.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-03-A-MODIFY-KEEPS-THE-MINIMUM-SAMPLING-INTERVAL, scope=function)
TEST_F(MonitoringHelperModify, AModifyKeepsTheMinimumSamplingInterval)
{
  const NodeId variable{1, 1100u};
  create_variable(variable, 500);
  const auto created = create_item(variable, handleX, 1000);
  ASSERT_TRUE(created.status.is_good()) << "the create answered " << to_string(created.status);
  EXPECT_GE(created.revisedSamplingInterval, 1000);
  ASSERT_TRUE(publish_until([&] { return report_count(handleX) >= 1; }))
    << "the initial value was not delivered";

  const auto to100 = modify_item(created.monitoredItemId, handleX, 100);
  ASSERT_TRUE(to100.status.is_good()) << "the modify to 100 answered " << to_string(to100.status);
  EXPECT_GE(to100.revisedSamplingInterval, 500) << "the modify to 100";

  const auto to0 = modify_item(created.monitoredItemId, handleX, 0);
  ASSERT_TRUE(to0.status.is_good()) << "the modify to 0 answered " << to_string(to0.status);
  EXPECT_GE(to0.revisedSamplingInterval, 500) << "the modify to 0";

  const auto before = report_count(handleX);
  for (const int32_t value : {1, 2, 3})
  {
    write_value(variable, value);
    std::this_thread::sleep_for(20ms);
  }
  publish_for(1500ms);

  const auto values = good_values_of(handleX, before);
  EXPECT_NE(std::find(values.begin(), values.end(), 3), values.end()) << reports_text(handleX);
  const bool reportedOne = std::find(values.begin(), values.end(), 1) != values.end();
  const bool reportedTwo = std::find(values.begin(), values.end(), 2) != values.end();
  EXPECT_FALSE(reportedOne && reportedTwo)
    << "every write was reported, not sampled; " << reports_text(handleX);
}

// COMP-SVR-NAMESPACE-MONITORING-HELPER-03 rule 1: the in-memory namespace marks a modified item as it marks a
// created one, so a Value item modified to 0 on a Variable without a minimum reports every change. A guard
// for B3's rewrite.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-03-A-MODIFY-TO-INTERVAL-0-OF-A-VALUE-WITHOUT-A-MINIMUM-REPORTS-EVERY-CHANGE, scope=function)
TEST_F(MonitoringHelperModify, AModifyToInterval0OfAValueWithoutAMinimumReportsEveryChange)
{
  const NodeId variable{1, 1200u};
  create_variable(variable, 0);
  const auto created = create_item(variable, handleX, 1000);
  ASSERT_TRUE(created.status.is_good()) << "the create answered " << to_string(created.status);
  ASSERT_TRUE(publish_until([&] { return report_count(handleX) >= 1; }))
    << "the initial value was not delivered";
  const auto before = report_count(handleX);

  const auto modified = modify_item(created.monitoredItemId, handleX, 0);
  ASSERT_TRUE(modified.status.is_good()) << "the modify answered " << to_string(modified.status);
  EXPECT_DOUBLE_EQ(modified.revisedSamplingInterval, 0);

  for (const int32_t value : {1, 2, 3})
  {
    write_value(variable, value);
    std::this_thread::sleep_for(10ms);
  }
  publish_for(500ms);

  EXPECT_EQ(good_values_of(handleX, before), (std::vector<int32_t>{1, 2, 3})) << reports_text(handleX);
}

// DL-68 (6): a registration holds the Node object it was created on. After N is deleted and a Variable is
// added again under its NodeId, an item on the new Variable receives its changes once the old item is
// deleted, and the old item reports Bad_NodeIdUnknown once and nothing after it.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-INVALIDATION-01-A-NODE-ADDED-AGAIN-IS-MONITORED-BY-ITS-OWN-ITEMS-ONLY, scope=function)
TEST_F(MonitoringHelperDeletion, ANodeAddedAgainIsMonitoredByItsOwnItemsOnly)
{
  const NodeId variable{1, 1300u};
  const StatusCode nodeIdUnknown{Status::BadNodeIdUnknown};
  create_variable(variable, 0);
  const auto first = create_item(variable, handleX, 0);
  ASSERT_TRUE(first.status.is_good()) << "I1 was created with " << to_string(first.status);
  ASSERT_TRUE(publish_until([&] { return report_count(handleX) >= 1; }))
    << "I1's initial value was not delivered";

  const auto deleted = mAddressSpace->try_delete_node_sync(variable, true);
  ASSERT_TRUE(deleted.is_good()) << "N's delete answered " << to_string(deleted.status_code());
  ASSERT_TRUE(publish_until([&] { return count_status(handleX, nodeIdUnknown) >= 1; }))
    << "I1 did not report Bad_NodeIdUnknown; " << reports_text(handleX);
  const auto firstAfterNotice = report_count(handleX);

  create_variable(variable, 0);
  const auto second = create_item(variable, handleY, 0);
  ASSERT_TRUE(second.status.is_good()) << "I2 was created with " << to_string(second.status);
  ASSERT_TRUE(publish_until([&] { return report_count(handleY) >= 1; }))
    << "I2's initial value was not delivered";
  const auto secondBefore = report_count(handleY);

  const auto released = delete_item(first.monitoredItemId);
  ASSERT_TRUE(released.is_good()) << "I1's delete answered " << to_string(released);

  for (const int32_t value : {1, 2, 3})
  {
    write_value(variable, value);
    std::this_thread::sleep_for(50ms);
  }
  publish_for(500ms);

  EXPECT_EQ(good_values_of(handleY, secondBefore), (std::vector<int32_t>{1, 2, 3}))
    << "I2: " << reports_text(handleY);
  EXPECT_EQ(count_status(handleX, nodeIdUnknown), 1u) << "I1: " << reports_text(handleX);
  EXPECT_EQ(report_count(handleX), firstAfterNotice)
    << "I1 reported after its notice; " << reports_text(handleX);
}

// COMP-SVR-NAMESPACE-MONITORING-HELPER-03 rule 3: an item modified from a sampled interval to 0 reports a
// value written since its last sample; the subscription does not read again on modify.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-03-A-MODIFY-FROM-SAMPLED-TO-REPORTED-DELIVERS-A-CHANGE-SINCE-THE-LAST-SAMPLE, scope=function)
TEST_F(MonitoringHelperModify, AModifyFromSampledToReportedDeliversAChangeSinceTheLastSample)
{
  const NodeId variable{1, 1400u};
  create_variable(variable, 0);
  write_value(variable, 5);
  const auto created = create_item(variable, handleX, 1000);
  ASSERT_TRUE(created.status.is_good()) << "the create answered " << to_string(created.status);
  ASSERT_TRUE(publish_until(
    [&]
    {
      const auto values = good_values_of(handleX);
      return std::find(values.begin(), values.end(), 5) != values.end();
    }))
    << "5 was not reported; " << reports_text(handleX);
  const auto before = report_count(handleX);

  write_value(variable, 6);
  const auto modified = modify_item(created.monitoredItemId, handleX, 0);
  ASSERT_TRUE(modified.status.is_good()) << "the modify answered " << to_string(modified.status);
  publish_for(1000ms);

  const auto values = good_values_of(handleX, before);
  EXPECT_NE(std::find(values.begin(), values.end(), 6), values.end()) << reports_text(handleX);
}

// Part 4 5.12.1.5: values reported for a Node before it is deleted are real changes, and are delivered, in
// order, before the deletion's Bad_NodeIdUnknown.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-INVALIDATION-01-VALUES-REPORTED-BEFORE-THE-DELETION-PRECEDE-THE-NOTICE, scope=function)
TEST_F(MonitoringHelperDeletion, ValuesReportedBeforeTheDeletionPrecedeTheNotice)
{
  const NodeId variable{1, 1500u};
  const StatusCode nodeIdUnknown{Status::BadNodeIdUnknown};
  create_variable(variable, 0);
  const auto created = create_item(variable, handleX, 0);
  ASSERT_TRUE(created.status.is_good()) << "the create answered " << to_string(created.status);
  ASSERT_TRUE(publish_until([&] { return report_count(handleX) >= 1; }))
    << "the initial value was not delivered";
  const auto before = report_count(handleX);

  for (const int32_t value : {1, 2, 3})
    write_value(variable, value);
  const auto deleted = mAddressSpace->try_delete_node_sync(variable, true);
  ASSERT_TRUE(deleted.is_good()) << "N's delete answered " << to_string(deleted.status_code());
  publish_for(1000ms);

  std::vector<std::string> sequence;
  const auto reports = reports_of(handleX);
  for (size_t index = before; index < reports.size(); ++index)
  {
    if (reports[index].status == nodeIdUnknown)
      sequence.emplace_back("Bad_NodeIdUnknown");
    else if (reports[index].status.is_good() && reports[index].value.is_int32())
      sequence.push_back(std::to_string(reports[index].value.as<int32_t>()));
    else
      sequence.push_back(to_string(reports[index].value) + " [" + to_string(reports[index].status) + "]");
  }
  EXPECT_EQ(sequence, (std::vector<std::string>{"1", "2", "3", "Bad_NodeIdUnknown"}))
    << reports_text(handleX);
}
