// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 4 section 5.12.1.1: "The item to be monitored may be any Node Attribute." A MonitoredItem on a
// VariableType's Value reports the type's Value as a Read of it returns it, initially and after each change,
// whatever its sampling interval, and the filter rules of the Value Attribute apply (delivery decision
// DL-31). Each test monitors T's Value with two items in one Subscription, one with the sampling interval 100
// ms (polled) and one with 0.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_attribute_id.h"
#include "ua_attribute_write_mask.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_deadband_type.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

constexpr uint32_t polledHandle = 1;
constexpr uint32_t onChangeHandle = 2;

class MonitoredVariableTypeValue : public ComplianceWithNodes
{
protected:
  struct Reported
  {
    uint32_t handle;
    Variant value;
    StatusCode status;
  };

  // A VariableType of @p dataType with ValueRank Scalar holding @p value, below BaseDataVariableType, whose
  // WriteMask sets bit 21 (ValueForVariableType).
  NodeId create_type(uint32_t id, const char* name, NodeId dataType, Variant value)
  {
    auto addressSpace = mServer.server().address_space();
    const NodeId typeId{mTestNamespaceIndex, id};
    auto created = addressSpace.try_create_node_sync(typeId, NodeClass::VariableType, {});
    EXPECT_TRUE(created.is_good()) << "the VariableType " << name << " could not be created";
    if (created.is_bad())
      return typeId;
    auto type = created.value();
    type.set_browse_name(QualifiedName{mTestNamespaceIndex, name});
    type.set_display_name(LocalizedText{"", name});
    auto variableType = type.as<VariableTypeAccessor>();
    EXPECT_TRUE(variableType.has_value());
    if (!variableType.has_value())
      return typeId;
    variableType->set_data_type(std::move(dataType));
    variableType->set_value_rank(ValueRank{ValueRank::scalar});
    variableType->set_value(DataValue{std::move(value)});
    type.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::ValueForVariableType});
    addressSpace.find_node_sync(NodeId{VariableTypeId::BaseDataVariableType})
      .add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, typeId);  // and its inverse half (NR-70 B8)
    return typeId;
  }

  /// Changes T's Value on the Server through VariableTypeAccessor::set_value.
  void set_value(const NodeId& typeId, Variant value)
  {
    auto type = mServer.server().address_space().find_node_sync(typeId).as<VariableTypeAccessor>();
    ASSERT_TRUE(type.has_value());
    type->set_value(DataValue{std::move(value)});
  }

  /// Creates a Subscription and the two items on @p typeId's Value, each with its own copy of @p filter when
  /// one is made; returns the Subscription's id.
  uint32_t monitor_both(
    const NodeId& typeId, const std::function<std::unique_ptr<DataChangeFilter>()>& filter = {})
  {
    const uint32_t subscriptionId =
      create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
    EXPECT_NE(subscriptionId, 0u);
    const std::pair<uint32_t, double> items[] = {{polledHandle, 100.0}, {onChangeHandle, 0.0}};
    for (const auto& [handle, interval] : items)
    {
      auto request = build_create_mi_request(subscriptionId,
        typeId,
        std::unique_ptr<Structure>{filter ? filter().release() : nullptr},
        {.clientHandle = handle, .samplingInterval = interval, .queueSize = 10U});
      auto response = mSession->monitored_items().try_create_monitored_items_sync(std::move(request));
      EXPECT_TRUE(response.is_good()) << to_string(response.status_code());
      if (response.is_bad() || response.value().results().size() != 1U)
        continue;
      EXPECT_THAT(response.value().results()[0].status_code(), Good())
        << "the item with the sampling interval " << interval << " ms";
    }
    return subscriptionId;
  }

  void publish_once()
  {
    auto response = try_publish_once(*mSession);
    if (!response)
      return;
    const auto* change = as_data_change(*response);
    if (change == nullptr)
      return;
    for (const auto& notification : change->monitored_items())
    {
      mReported.push_back({notification.client_handle(),
        notification.value().value(),
        notification.value().status().value_or(StatusCode{Status::Good})});
    }
  }

  /// Publishes, recording every notification, until @p done holds or 5 s pass. Returns whether it held.
  bool publish_until(const std::function<bool()>& done)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline)
    {
      publish_once();
      if (done())
        return true;
    }
    return done();
  }

  /// Publishes for @p duration, recording every notification.
  void publish_for(std::chrono::milliseconds duration)
  {
    const auto deadline = std::chrono::steady_clock::now() + duration;
    while (std::chrono::steady_clock::now() < deadline)
      publish_once();
  }

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

  bool both_reported() const
  {
    return !reports_of(polledHandle).empty() && !reports_of(onChangeHandle).empty();
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
TEST_F(MonitoredVariableTypeValue, EveryNotificationCarriesTheTypesValue)
{
  const auto typeId =
    create_type(7700u, "MonitoredFirstType", NodeId{DataTypeId::Int32}, Variant{int32_t{7}});
  monitor_both(typeId);
  publish_until([&] { return both_reported(); });

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

// DL-31: F7 lets a Client write a VariableType's Value; both items then report the value written.
// @relation(AC-SVR-MI-GEN-076-CLIENT-WRITE-REPORTED, scope=function)
TEST_F(MonitoredVariableTypeValue, AClientWriteIsReportedByBothItems)
{
  const auto typeId =
    create_type(7701u, "MonitoredWrittenType", NodeId{DataTypeId::Int32}, Variant{int32_t{7}});
  monitor_both(typeId);
  ASSERT_TRUE(publish_until([&] { return both_reported(); })) << "the items never reported";

  WriteRequestBuilder builder;
  builder.write(typeId, Variant{int32_t{9}});
  auto written = mSession->attributes().write_sync(builder.build());
  ASSERT_THAT(written, ServiceResultIsGood());
  ASSERT_EQ(written.results().size(), 1u);
  EXPECT_THAT(written.results()[0], HasStatus(Status::Good)) << "the Write of T's Value";

  const Variant nine{int32_t{9}};
  publish_until([&] { return reported_good(polledHandle, nine) && reported_good(onChangeHandle, nine); });
  EXPECT_TRUE(reported_good(polledHandle, nine)) << "the polled item: " << reports_text(polledHandle);
  EXPECT_TRUE(reported_good(onChangeHandle, nine))
    << "the item with sampling interval 0: " << reports_text(onChangeHandle);
}

// DL-31: the item reports "the value, not the held form": a change made through set_value is reported as a
// Variant holding Int32 9, not the DataValue the in-memory Node holds (DL-20).
// @relation(AC-SVR-MI-GEN-076-NOTIFICATION-CARRIES-THE-VALUE, scope=function)
TEST_F(MonitoredVariableTypeValue, ANotificationCarriesTheValueNotTheHeldForm)
{
  const auto typeId = create_type(7702u, "MonitoredHeldType", NodeId{DataTypeId::Int32}, Variant{int32_t{7}});
  monitor_both(typeId);
  ASSERT_TRUE(publish_until([&] { return both_reported(); })) << "the items never reported";

  set_value(typeId, Variant{int32_t{9}});
  const Variant nine{int32_t{9}};
  publish_until([&] { return reported_good(polledHandle, nine) && reported_good(onChangeHandle, nine); });
  EXPECT_TRUE(reported_good(polledHandle, nine)) << "the polled item: " << reports_text(polledHandle);
  EXPECT_TRUE(reported_good(onChangeHandle, nine))
    << "the item with sampling interval 0: " << reports_text(onChangeHandle);
}

// Part 4 section 7.22.2, Table 146: an AbsoluteDeadband reports a change when it differs from the last value
// pushed by more than the deadband. DL-31 applies the Value Attribute's filter rules: 3.0 differs from 1.0
// by 2.0, inside 5.0, and 10.0 by 9.0. More than 100 ms pass between the changes.
// @relation(AC-SVR-MI-GEN-076-ABSOLUTE-DEADBAND-APPLIES, scope=function)
TEST_F(MonitoredVariableTypeValue, AnAbsoluteDeadbandSuppressesAChangeInsideIt)
{
  const auto typeId = create_type(7703u, "MonitoredDeadbandType", NodeId{DataTypeId::Double}, Variant{1.0});
  monitor_both(typeId, [] { return absolute_deadband(5.0); });
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
