// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// A MonitoredItem on a VariableType's Value reports the type's Value as a Read of it returns it, initially
// and after each change, whatever its sampling interval, and the filter rules of the Value Attribute apply
// (Part 4 section 5.12.1.1, "The item to be monitored may be any Node Attribute"; delivery decision DL-31).
//
// The Subscription is driven as the pipeline drives it: CreateMonitoredItems through its asynchronous entry,
// the values reaching it through the in-memory namespace's monitoring of a real VariableType, and the
// notifications taken by fulfill_publish. Each test creates two items on T's Value, one polled (sampling
// interval 100 ms) and one notified on change (sampling interval 0), the two ways an item is sampled.

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "test_utilities.h"

#include "ua_subscription.h"
#include "ua_subscription_test_access.h"

#include "ua_address_space.h"
#include "ua_attribute_write_mask.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_data_change_notification.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_deadband_type.h"
#include "ua_node_accessor.h"
#include "ua_node_utilities.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variant.h"

#include <boost/asio/thread_pool.hpp>

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

constexpr uint32_t polledHandle = 1;
constexpr uint32_t onChangeHandle = 2;

class VariableTypeValueMonitoring : public ::testing::Test
{
protected:
  struct Reported
  {
    uint32_t handle;
    Variant value;
    StatusCode status;
  };

  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test:variable-type-value-monitoring", mExecutor));
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

  /// A VariableType of @p dataType with ValueRank Scalar holding @p value, whose WriteMask sets bit 21.
  NodeId create_type(uint32_t identifier, NodeId dataType, Variant value)
  {
    const NodeId typeId{1, identifier};
    auto created = mAddressSpace->try_create_node_sync(typeId, NodeClass::VariableType, {});
    EXPECT_TRUE(created.is_good()) << "the VariableType could not be created";
    if (created.is_bad())
      return typeId;
    auto type = created.value().as<VariableTypeAccessor>();
    EXPECT_TRUE(type.has_value());
    if (!type.has_value())
      return typeId;
    type->set_data_type(std::move(dataType));
    type->set_value_rank(ValueRank{ValueRank::scalar});
    type->set_value(DataValue{std::move(value)});
    type->set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ValueForVariableType});
    return typeId;
  }

  /// Changes T's Value on the Server through VariableTypeAccessor::set_value.
  void set_value(const NodeId& typeId, Variant value)
  {
    auto type = mAddressSpace->find_node_sync(typeId).as<VariableTypeAccessor>();
    ASSERT_TRUE(type.has_value());
    type->set_value(DataValue{std::move(value)});
  }

  /// Creates the item with @p clientHandle on @p typeId's Value; returns its StatusCode.
  StatusCode create_item(const NodeId& typeId, uint32_t clientHandle, Duration samplingInterval,
    std::unique_ptr<DataChangeFilter> filter = nullptr)
  {
    MonitoredItemCreateRequest item;
    item.item_to_monitor().node_id() = typeId;
    item.item_to_monitor().attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters().client_handle() = clientHandle;
    item.requested_parameters().sampling_interval() = samplingInterval;
    item.requested_parameters().queue_size() = 10;
    item.requested_parameters().discard_oldest() = true;
    if (filter)
      item.requested_parameters().filter().inner_unique_ptr() = std::move(filter);

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
      return StatusCode{Status::BadTimeout};
    }
    auto results = future.get();
    if (results.size() != 1u)
    {
      ADD_FAILURE() << "the create answered " << results.size() << " results for one item";
      return StatusCode{Status::BadInternalError};
    }
    return results[0].status_code();
  }

  /// Creates both items on @p typeId's Value, each with its own copy of @p filter when one is made.
  void create_both(
    const NodeId& typeId, const std::function<std::unique_ptr<DataChangeFilter>()>& filter = {})
  {
    const auto polled = create_item(typeId, polledHandle, 100.0, filter ? filter() : nullptr);
    EXPECT_TRUE(polled.is_good()) << "the polled item was created with " << to_string(polled);
    const auto onChange = create_item(typeId, onChangeHandle, 0.0, filter ? filter() : nullptr);
    EXPECT_TRUE(onChange.is_good()) << "the item with sampling interval 0 was created with "
                                    << to_string(onChange);
  }

  /// Publishes, recording every notification, until @p done holds or 3 s pass. Returns whether it held.
  bool publish_until(const std::function<bool()>& done)
  {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
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

  /// Whether the item with @p clientHandle reported @p value with a Good status, the value a Variant holding
  /// it rather than a DataValue.
  bool reported_good(uint32_t clientHandle, const Variant& value) const
  {
    for (const auto& reported : reports_of(clientHandle))
    {
      if (reported.status.is_good() && !reported.value.is_data_value() &&
          to_string(reported.value) == to_string(value))
        return true;
    }
    return false;
  }

  std::string reports_text(uint32_t clientHandle) const
  {
    std::string text = "the item reported:";
    for (const auto& reported : reports_of(clientHandle))
    {
      text += " " + to_string(reported.value) + (reported.value.is_data_value() ? " (a DataValue)" : "") +
              " [" + to_string(reported.status) + "];";
    }
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

std::unique_ptr<DataChangeFilter> absolute_deadband(double value)
{
  auto filter = std::make_unique<DataChangeFilter>();
  filter->trigger() = DataChangeTrigger::StatusValue;
  filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
  filter->deadband_value() = value;
  return filter;
}

}  // namespace

// DL-31: each item's first notification is T's Value, 7, with a Good status (a guard: the create reads it
// through the attribute read), and no notification in the next three sampling intervals of the polled item
// (300 ms), the Value unchanged, has another status or value: a polled sample read through read_value would
// answer Bad_AttributeIdInvalid with a null value.
// @relation(AC-SVR-MI-GEN-076-FIRST-NOTIFICATION-IS-THE-VALUE, scope=function)
TEST_F(VariableTypeValueMonitoring, EverySampleIsTheTypesValue)
{
  const auto typeId = create_type(100u, NodeId{DataTypeId::Int32}, Variant{int32_t{7}});
  create_both(typeId);
  publish_until([&] { return !reports_of(polledHandle).empty() && !reports_of(onChangeHandle).empty(); });

  const Variant seven{int32_t{7}};
  for (const auto handle : {polledHandle, onChangeHandle})
  {
    const auto reports = reports_of(handle);
    ASSERT_FALSE(reports.empty()) << "item " << handle << " reported nothing";
    EXPECT_TRUE(reports.front().status.is_good())
      << "item " << handle << ": the first notification has the status " << to_string(reports.front().status);
    EXPECT_EQ(to_string(reports.front().value), to_string(seven))
      << "item " << handle << ": the first notification";
  }

  publish_for(300ms);
  for (const auto handle : {polledHandle, onChangeHandle})
  {
    const auto reports = reports_of(handle);
    for (size_t index = 1; index < reports.size(); ++index)
    {
      EXPECT_TRUE(reports[index].status.is_good() && to_string(reports[index].value) == to_string(seven))
        << "item " << handle << " later reported " << to_string(reports[index].value) << " ["
        << to_string(reports[index].status) << "]";
    }
  }
}

// DL-31: a write of T's Value through the Node's attribute write, the path the Write service takes for a
// VariableType's Value, is reported by both items with the value 9 and a Good status.
// @relation(AC-SVR-MI-GEN-076-CLIENT-WRITE-REPORTED, scope=function)
TEST_F(VariableTypeValueMonitoring, AnAttributeWriteIsReportedToBothKindsOfItem)
{
  const auto typeId = create_type(110u, NodeId{DataTypeId::Int32}, Variant{int32_t{7}});
  create_both(typeId);
  ASSERT_TRUE(
    publish_until([&] { return !reports_of(polledHandle).empty() && !reports_of(onChangeHandle).empty(); }))
    << "the items never reported";

  auto node = mAddressSpace->find_node_sync(typeId);
  EXPECT_NO_THROW(node_utils::write_node_sync_attribute(node, AttributeId::Value, Variant{int32_t{9}}))
    << "the attribute write of T's Value was refused";
  const Variant nine{int32_t{9}};
  publish_until([&] { return reported_good(polledHandle, nine) && reported_good(onChangeHandle, nine); });
  EXPECT_TRUE(reported_good(polledHandle, nine)) << "the polled item: " << reports_text(polledHandle);
  EXPECT_TRUE(reported_good(onChangeHandle, nine))
    << "the item with sampling interval 0: " << reports_text(onChangeHandle);
}

// DL-31: the item reports "the value, not the held form". The in-memory namespace holds a VariableType's
// Value as a DataValue inside the Variant (DL-20); a change made through set_value is reported as a Variant
// holding Int32 9.
// @relation(AC-SVR-MI-GEN-076-NOTIFICATION-CARRIES-THE-VALUE, scope=function)
TEST_F(VariableTypeValueMonitoring, AChangeNotificationCarriesTheValueNotTheHeldForm)
{
  const auto typeId = create_type(120u, NodeId{DataTypeId::Int32}, Variant{int32_t{7}});
  create_both(typeId);
  ASSERT_TRUE(
    publish_until([&] { return !reports_of(polledHandle).empty() && !reports_of(onChangeHandle).empty(); }))
    << "the items never reported";

  set_value(typeId, Variant{int32_t{9}});
  const Variant nine{int32_t{9}};
  publish_until([&] { return reported_good(polledHandle, nine) && reported_good(onChangeHandle, nine); });
  EXPECT_TRUE(reported_good(polledHandle, nine)) << "the polled item: " << reports_text(polledHandle);
  EXPECT_TRUE(reported_good(onChangeHandle, nine))
    << "the item with sampling interval 0: " << reports_text(onChangeHandle);
}

// Part 4 section 7.22.2, Table 146: an AbsoluteDeadband reports a change when it differs from the last value
// pushed by more than the deadband. DL-31 applies the Value Attribute's filter rules to a VariableType's
// Value: 3.0 differs from 1.0 by 2.0, inside 5.0, and 10.0 by 9.0. More than 100 ms pass between the changes,
// so the polled item samples 3.0 before 10.0 is set.
// @relation(AC-SVR-MI-GEN-076-ABSOLUTE-DEADBAND-APPLIES, scope=function)
TEST_F(VariableTypeValueMonitoring, AnAbsoluteDeadbandSuppressesAChangeInsideIt)
{
  const auto typeId = create_type(130u, NodeId{DataTypeId::Double}, Variant{1.0});
  create_both(typeId, [] { return absolute_deadband(5.0); });
  const Variant one{1.0};
  publish_until([&] { return reported_good(polledHandle, one) && reported_good(onChangeHandle, one); });
  EXPECT_TRUE(reported_good(polledHandle, one)) << "the polled item: " << reports_text(polledHandle);
  EXPECT_TRUE(reported_good(onChangeHandle, one))
    << "the item with sampling interval 0: " << reports_text(onChangeHandle);

  set_value(typeId, Variant{3.0});
  publish_for(400ms);
  set_value(typeId, Variant{10.0});
  const Variant ten{10.0};
  publish_until([&] { return reported_good(polledHandle, ten) && reported_good(onChangeHandle, ten); });

  const Variant three{3.0};
  for (const auto handle : {polledHandle, onChangeHandle})
  {
    EXPECT_TRUE(reported_good(handle, ten)) << "item " << handle << ": " << reports_text(handle);
    // Whatever form a notification takes, the value it carries is compared: a DataValue is looked into.
    bool reportedThree = false;
    for (const auto& reported : reports_of(handle))
    {
      const auto carried =
        reported.value.is_data_value() ? reported.value.as<DataValue>().value() : reported.value;
      reportedThree = reportedThree || to_string(carried) == to_string(three);
    }
    EXPECT_FALSE(reportedThree) << "item " << handle << " reported 3.0, inside the deadband; "
                                << reports_text(handle);
  }
}
