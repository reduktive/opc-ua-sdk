// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration mirror for CTT Data Access Analog 008 (SemanticsChanged).
///
/// Proves the full SDK path end-to-end: an AnalogItem created through the generated helper
/// (AnalogItem::create_sync) has an EURange Property holding the inverse HasProperty Reference to it,
/// from which the in-memory namespace finds the AnalogItem when the EURange changes and marks its
/// monitored items, so a client Write to EURange delivers a data-change on the item's Value carrying
/// StatusCode Good | SemanticsChanged - through a deadband, with the value itself unchanged. This
/// exercises the instantiation + the namespace's write path + the MonitoredItem arm/apply/clear
/// delivery in one shot.

#include "compliance_helpers.h"
#include "requests.h"
#include "subscription.h"

#include "ua_analog_item.h"
#include "ua_create_monitored_items_request.h"
#include "ua_data_change_filter.h"
#include "ua_deadband_type.h"
#include "ua_range.h"
#include "ua_value_rank.h"
#include "ua_access_level_type.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_to_string.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

class ComplianceSemanticsChanged : public ComplianceWithSession
{
protected:
  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    mTestNamespace = default_ns::Namespace::create("urn:test:semantics", mServer.thread_pool().executor());
    mTestNamespaceIndex = addressSpace.add_namespace_sync(mTestNamespace);

    // Create an AnalogItem through the generated helper. Its EURange Property holds the inverse
    // HasProperty Reference to it, from which the namespace marks the AnalogItem's monitored items
    // SemanticsChanged when the EURange changes.
    InstantiationOptions options;
    options.targetNamespaceIndex = mTestNamespaceIndex;
    VariableInstantiationAttributes attrs{.dataType = NodeId{DataTypeId::Double},
      .valueRank = ValueRank::scalar,
      .accessLevel = AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite}};

    auto analog = AnalogItem::create_sync(addressSpace,
      NodeId{ObjectId::ObjectsFolder},
      QualifiedName{mTestNamespaceIndex, "ProcessValue"},
      options,
      attrs);
    mAnalogId = analog.node_id();
    mEuRangeId = analog.eu_range_property_sync().node_id();
    // Release the handle's owned subtree so the instantiated nodes persist in the address space
    // (the handle would otherwise remove them when it goes out of scope).
    analog.release();

    // Seed an initial Value (the deadband baseline) and an initial EURange, and make EURange
    // client-writable (the instantiation engine materialises Properties read-only).
    auto analogVar = addressSpace.find_node_sync(mAnalogId).as<VariableAccessor>();
    ASSERT_TRUE(analogVar.has_value());
    analogVar->write_value_sync(double{50.0});

    auto euRangeVar = addressSpace.find_node_sync(mEuRangeId).as<VariableAccessor>();
    ASSERT_TRUE(euRangeVar.has_value());
    euRangeVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    Range initialRange;
    initialRange.low() = 0.0;
    initialRange.high() = 100.0;
    euRangeVar->write_value_sync(Variant{initialRange});
  }

  /// Create a Value monitor on the AnalogItem with an absolute deadband (mirrors 008: a deadband so
  /// a plain re-sample of the unchanged value is suppressed - only the SemanticsChanged bit gets
  /// through). Returns the monitored-item id.
  uint32_t create_deadband_monitor(
    uint32_t subscriptionId, uint32_t clientHandle, double samplingInterval = 50.0)
  {
    ReadValueId rv;
    rv.node_id() = mAnalogId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

    auto filter = std::make_unique<DataChangeFilter>();
    filter->trigger() = DataChangeTrigger::StatusValue;
    filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Absolute);
    filter->deadband_value() = 10.0;

    MonitoringParameters params;
    params.client_handle() = clientHandle;
    params.sampling_interval() = samplingInterval;
    params.queue_size() = 1;
    params.discard_oldest() = true;
    params.filter() = std::move(filter);

    MonitoredItemCreateRequest item;
    item.item_to_monitor() = std::move(rv);
    item.monitoring_mode() = MonitoringMode::Reporting;
    item.requested_parameters() = std::move(params);

    CreateMonitoredItemsRequest req;
    req.subscription_id() = subscriptionId;
    req.timestamps_to_return() = TimestampsToReturn::Both;
    req.items_to_create().push_back(std::move(item));

    auto resp = mSession->monitored_items().create_monitored_items_sync(std::move(req));
    EXPECT_EQ(resp.results().size(), 1u);
    EXPECT_TRUE(resp.results()[0].status_code().is_good())
      << "0x" << std::hex << resp.results()[0].status_code().as_uint32();
    return resp.results()[0].monitored_item_id();
  }

  std::shared_ptr<default_ns::Namespace> mTestNamespace;
  uint16_t mTestNamespaceIndex{0};
  NodeId mAnalogId;
  NodeId mEuRangeId;
};

}  // namespace

// CTT Data Access Analog 008: writing EURange delivers Good | SemanticsChanged on the item's Value.
// @verifies AC-SVR-ADDRSP-089-SEMANTICSCHANGED-BIT
TEST_F(ComplianceSemanticsChanged, WritingEuRangeDeliversSemanticsChangedBit)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
  const uint32_t clientHandle = 7;
  create_deadband_monitor(subId, clientHandle);

  // Publish #1: drain the initial Value (no SemanticsChanged bit).
  auto initial = wait_for_data_change(*mSession,
    subId,
    [&](const DataChangeNotification& dc)
    {
      return std::any_of(dc.monitored_items().begin(),
        dc.monitored_items().end(),
        [&](const auto& mi) { return mi.client_handle() == clientHandle; });
    });
  ASSERT_TRUE(initial);

  // Client Write to EURange - the value of ProcessValue itself does not change.
  Range newRange;
  newRange.low() = 0.0;
  newRange.high() = 200.0;
  write_value_async(*mSession, mEuRangeId, Variant{newRange});

  // Publish #2: a data-change on the Value carrying Good | SemanticsChanged (bypassing the deadband).
  auto carriesBit = [&](const DataChangeNotification& dc)
  {
    return std::any_of(dc.monitored_items().begin(),
      dc.monitored_items().end(),
      [&](const auto& mi)
      {
        return mi.client_handle() == clientHandle && mi.value().status().has_value() &&
               mi.value().status()->semantics_changed();
      });
  };
  auto changed = wait_for_data_change(*mSession, subId, carriesBit, 2s);
  ASSERT_TRUE(changed) << "expected a DataChange carrying the SemanticsChanged bit after EURange write";

  for (const auto& mi : changed->monitored_items())
  {
    if (mi.client_handle() == clientHandle)
    {
      ASSERT_TRUE(mi.value().status().has_value());
      EXPECT_TRUE(mi.value().status()->semantics_changed());
      EXPECT_TRUE(mi.value().status()->is_good());  // Good | SemanticsChanged
    }
  }
}

// The CTT's Data Access Semantic Changes 003 order: the item is created and EURange is written before the
// Client has published anything. The initial value is still queued, unsent, and it is the next DataChange
// the Client receives - so it is the one that must carry SemanticsChanged. A server that waited for a
// later sample instead sent the initial value without the bit, and a steady value sends no later sample.
TEST_F(ComplianceSemanticsChanged, APropertyChangeBeforeTheFirstPublishMarksTheQueuedInitialValue)
{
  auto subId = create_subscription(*mSession, {.publishingInterval = 1000.0, .lifetimeCount = 100});
  const uint32_t clientHandle = 9;
  // Sampling interval 0 on a Variable whose MinimumSamplingInterval is 0 is exception-based sampling: a
  // value is taken only when the Variable is written. A steady value then produces no sample at all that
  // could carry the bit later.
  create_deadband_monitor(subId, clientHandle, /*samplingInterval=*/0.0);

  Range newRange;
  newRange.low() = 0.0;
  newRange.high() = 150.0;
  write_value_async(*mSession, mEuRangeId, Variant{newRange});

  auto first = wait_for_data_change(
    *mSession,
    subId,
    [&](const DataChangeNotification& dc)
    {
      return std::any_of(dc.monitored_items().begin(),
        dc.monitored_items().end(),
        [&](const auto& mi) { return mi.client_handle() == clientHandle; });
    },
    3s);
  ASSERT_TRUE(first) << "no DataChange for the item";
  for (const auto& mi : first->monitored_items())
  {
    if (mi.client_handle() != clientHandle)
      continue;
    ASSERT_TRUE(mi.value().status().has_value()) << "the first DataChange carries no status, so no bit";
    EXPECT_TRUE(mi.value().status()->semantics_changed())
      << "the first DataChange after the EURange write must carry SemanticsChanged";
  }
}

// ============================================================================================================
// PercentDeadband: a PercentDeadband item's range follows its EURange Property (Part 8 sections 6.2
// and 5.3.2.2; NR-62; NR-70 F16). The AnalogItem is created through the generated helper, so a Client Write
// to its EURange is marked SemanticsChanged by the namespace, as in production. The fixture is the secured
// one because it captures the server log.
// ============================================================================================================

namespace
{

class PercentDeadband : public ComplianceSecuredWithSession
{
protected:
  static constexpr uint32_t sItemHandle = 31;

  struct Reported
  {
    double value;
    bool semanticsChanged;
  };

  void SetUp() override
  {
    ComplianceSecuredWithSession::SetUp();
    auto addressSpace = mServer->address_space();
    auto percentNamespace =
      default_ns::Namespace::create("urn:test:percent-deadband", mServerThreadPool.get_executor());
    mNsIndex = addressSpace.add_namespace_sync(percentNamespace);
    grant_fixture_namespace_permissions(addressSpace);
    const AccessLevelType readWrite{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite};

    InstantiationOptions options;
    options.targetNamespaceIndex = mNsIndex;
    VariableInstantiationAttributes attributes{
      .dataType = NodeId{DataTypeId::Double}, .valueRank = ValueRank::scalar, .accessLevel = readWrite};
    auto analog = AnalogItem::create_sync(addressSpace,
      NodeId{ObjectId::ObjectsFolder},
      QualifiedName{mNsIndex, "PercentDeadbandItem"},
      options,
      attributes);
    mAnalogId = analog.node_id();
    mEuRangeId = analog.eu_range_property_sync().node_id();
    analog.release();
    auto analogVariable = addressSpace.find_node_sync(mAnalogId).as<VariableAccessor>();
    ASSERT_TRUE(analogVariable.has_value());
    analogVariable->write_value_sync(double{0.0});
    auto euRange = addressSpace.find_node_sync(mEuRangeId).as<VariableAccessor>();
    ASSERT_TRUE(euRange.has_value());
    euRange->set_access_level(readWrite);
    euRange->write_value_sync(Variant{make_range(0.0, 100.0)});

    // A Double Variable with no EURange Property.
    mPlainId = NodeId{mNsIndex, uint32_t{9100}};
    auto plain = addressSpace.create_node_sync(mPlainId, NodeClass::Variable);
    auto plainVariable = plain.as<VariableAccessor>();
    ASSERT_TRUE(plainVariable.has_value());
    plainVariable->set_browse_name(QualifiedName{mNsIndex, "PlainDouble"});
    plainVariable->set_display_name(LocalizedText{"", "PlainDouble"});
    plainVariable->set_data_type(NodeId{DataTypeId::Double});
    plainVariable->set_access_level(readWrite);
    plainVariable->write_value_sync(double{0.0});
  }

  static Range make_range(double low, double high)
  {
    Range range;
    range.low() = low;
    range.high() = high;
    return range;
  }

  static std::unique_ptr<DataChangeFilter> percent_deadband(double percent)
  {
    auto filter = std::make_unique<DataChangeFilter>();
    filter->trigger() = DataChangeTrigger::StatusValue;
    filter->deadband_type() = static_cast<uint32_t>(DeadbandType::Percent);
    filter->deadband_value() = percent;
    return filter;
  }

  uint32_t subscribe()
  {
    const uint32_t subscriptionId =
      create_subscription(*mSession, {.publishingInterval = 50.0, .lifetimeCount = 100});
    EXPECT_NE(subscriptionId, 0u);
    return subscriptionId;
  }

  /// Monitors @p node's Value with @p filter (none when null) and takes the initial value. Returns the item's
  /// id.
  uint32_t monitor(uint32_t subscriptionId, const NodeId& node, std::unique_ptr<DataChangeFilter> filter)
  {
    auto request = build_create_mi_request(subscriptionId,
      node,
      std::unique_ptr<Structure>{std::move(filter)},
      {.clientHandle = sItemHandle, .samplingInterval = 0.0, .queueSize = 10U});
    auto response = mSession->monitored_items().try_create_monitored_items_sync(std::move(request));
    EXPECT_TRUE(response.is_good()) << to_string(response.status_code());
    if (response.is_bad() || response.value().results().size() != 1U)
    {
      return 0;
    }
    const auto& result = response.value().results()[0];
    EXPECT_TRUE(result.status_code().is_good()) << to_string(result.status_code());
    EXPECT_TRUE(await_value(0.0)) << "the initial value was not published";
    return result.monitored_item_id();
  }

  StatusCode modify(
    uint32_t subscriptionId, uint32_t monitoredItemId, std::unique_ptr<DataChangeFilter> filter)
  {
    ModifyMonitoredItemsRequest request;
    request.subscription_id() = subscriptionId;
    request.timestamps_to_return() = TimestampsToReturn::Both;
    MonitoredItemModifyRequest item;
    item.monitored_item_id() = monitoredItemId;
    item.requested_parameters().client_handle() = sItemHandle;
    item.requested_parameters().sampling_interval() = 0.0;
    item.requested_parameters().queue_size() = 10U;
    item.requested_parameters().discard_oldest() = true;
    if (filter)
    {
      item.requested_parameters().filter() = std::unique_ptr<Structure>{std::move(filter)};
    }
    request.items_to_modify().push_back(std::move(item));
    auto response = mSession->monitored_items().modify_monitored_items_sync(std::move(request));
    EXPECT_EQ(response.results().size(), 1U);
    return response.results().empty() ? StatusCode{Status::BadUnexpectedError}
                                      : response.results()[0].status_code();
  }

  void write(const NodeId& node, double value)
  {
    write_value_async(*mSession, node, Variant{value});
  }

  void write_eu_range(double low, double high)
  {
    write_value_async(*mSession, mEuRangeId, Variant{make_range(low, high)});
  }

  /// Takes one Publish response and records what the item reported in it.
  void publish_once()
  {
    auto response = try_publish_once(*mSession);
    if (!response)
    {
      return;
    }
    const auto* change = as_data_change(*response);
    if (change == nullptr)
    {
      return;
    }
    for (const auto& notification : change->monitored_items())
    {
      if (notification.client_handle() != sItemHandle)
      {
        continue;
      }
      const auto* number = notification.value().value().try_as<double>();
      mReported.push_back({number != nullptr ? *number : std::nan(""),
        notification.value().status().has_value() && notification.value().status()->semantics_changed()});
    }
  }

  /// Publishes until the item reports @p value, at most 3 s.
  bool await_value(double value)
  {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (std::chrono::steady_clock::now() < deadline)
    {
      publish_once();
      if (reported(value))
      {
        return true;
      }
    }
    return false;
  }

  /// Publishes for @p window, recording whatever the item reports.
  void observe(std::chrono::milliseconds window = 700ms)
  {
    const auto deadline = std::chrono::steady_clock::now() + window;
    while (std::chrono::steady_clock::now() < deadline)
    {
      publish_once();
    }
  }

  bool reported(double value, bool semanticsChanged = false) const
  {
    return std::any_of(mReported.begin(),
      mReported.end(),
      [&](const Reported& entry)
      { return entry.value == value && (!semanticsChanged || entry.semanticsChanged); });
  }

  std::string reports() const
  {
    std::ostringstream text;
    text << "the item reported:";
    for (const auto& entry : mReported)
    {
      text << ' ' << entry.value << (entry.semanticsChanged ? "(SemanticsChanged)" : "");
    }
    return text.str();
  }

  /// Changes the EURange and writes @p value with publishing disabled, then waits so that the value reaches
  /// the item before anything is published: the value is the first the Client receives after the change.
  void change_eu_range_then_write(uint32_t subscriptionId, double low, double high, double value)
  {
    set_publishing_mode(*mSession, subscriptionId, false);
    write_eu_range(low, high);
    write(mAnalogId, value);
    std::this_thread::sleep_for(300ms);
    set_publishing_mode(*mSession, subscriptionId, true);
  }

  uint16_t mNsIndex{0};
  NodeId mAnalogId;
  NodeId mEuRangeId;
  NodeId mPlainId;
  std::vector<Reported> mReported;
};

}  // namespace

// Part 8 section 6.2: the deadband is (deadbandValue/100) * (high - low) of the EURange; section 5.3.2.2
// marks the item SemanticsChanged when the EURange changes; NR-62 makes the deadband the new range's.
// @relation(AC-SVR-DA-022-DEADBAND-FOLLOWS-EURANGE-CHANGE, scope=function)
TEST_F(PercentDeadband, FollowsAnEuRangeChange)
{
  const uint32_t subscriptionId = subscribe();
  ASSERT_NE(monitor(subscriptionId, mAnalogId, percent_deadband(10.0)), 0u);

  write(mAnalogId, 5.0);
  observe();
  change_eu_range_then_write(subscriptionId, 0.0, 20.0, 1.0);
  EXPECT_TRUE(await_value(1.0)) << reports();
  write(mAnalogId, 4.0);
  EXPECT_TRUE(await_value(4.0)) << "4.0, a change of 3, is above the deadband of 2 that {0, 20} gives; "
                                << reports();
  write(mAnalogId, 5.0);
  observe();

  EXPECT_TRUE(reported(1.0, /*semanticsChanged=*/true)) << reports();
  EXPECT_FALSE(reported(5.0)) << "neither write of 5.0 is outside the deadband in force; " << reports();
}

// Part 8 section 6.2's formula gives {50, 50} a deadband of 0, so every change is reported, and the server
// logs that the item's range is no longer usable. (That the warning names the item is observed in the unit
// arm: the captured server log here keeps the message, not its fields.)
// @relation(AC-SVR-DA-022-UNUSABLE-EURANGE-REPORTS-EVERY-CHANGE, scope=function)
TEST_F(PercentDeadband, AnUnusableEuRangeMakesTheItemReportEveryChange)
{
  const uint32_t subscriptionId = subscribe();
  ASSERT_NE(monitor(subscriptionId, mAnalogId, percent_deadband(10.0)), 0u);

  change_eu_range_then_write(subscriptionId, 50.0, 50.0, 1.0);
  EXPECT_TRUE(await_value(1.0)) << reports();
  write(mAnalogId, 2.0);
  EXPECT_TRUE(await_value(2.0)) << reports();
  write(mAnalogId, 2.5);
  EXPECT_TRUE(await_value(2.5)) << reports();

  const auto records = mServerLogSink->records();
  const bool warned = std::any_of(records.begin(),
    records.end(),
    [](const CapturingLogSink::Entry& entry)
    {
      return entry.level == LogLevel::Warning && entry.category == "subscription" &&
             entry.message ==
               "A PercentDeadband item's EURange is no longer a usable range; the item reports every change";
    });
  EXPECT_TRUE(warned) << "no warning in the category subscription that the item's range is not usable";
}

// Part 4 section 5.12.3.1: a modify is applied at once; Part 8 section 6.2 defines the PercentDeadband by the
// EURange.
// @relation(AC-SVR-DA-022-MODIFY-TO-PERCENT-USES-EURANGE, scope=function)
TEST_F(PercentDeadband, ModifyToPercentDeadbandUsesTheEuRange)
{
  const uint32_t subscriptionId = subscribe();
  const uint32_t item = monitor(subscriptionId, mAnalogId, nullptr);
  ASSERT_NE(item, 0u);

  const auto modified = modify(subscriptionId, item, percent_deadband(10.0));
  EXPECT_TRUE(modified.is_good()) << to_string(modified);
  write(mAnalogId, 5.0);
  observe();
  write(mAnalogId, 20.0);
  EXPECT_TRUE(await_value(20.0)) << reports();

  EXPECT_FALSE(reported(5.0)) << "a change of 5 is within the deadband of 10; " << reports();
}

// Part 8 Table 29: a PercentDeadband is not supported where no EURange is configured. The ErrorDetail
// (PercentDeadbandWithoutEuRange) does not cross the wire on ModifyMonitoredItems; the unit arm observes it.
// @relation(AC-SVR-DA-022-MODIFY-TO-PERCENT-WITHOUT-EURANGE-REFUSED, scope=function)
TEST_F(PercentDeadband, AModifyToPercentDeadbandWithoutEuRangeIsRefused)
{
  const uint32_t subscriptionId = subscribe();
  const uint32_t item = monitor(subscriptionId, mPlainId, nullptr);
  ASSERT_NE(item, 0u);

  const auto modified = modify(subscriptionId, item, percent_deadband(10.0));
  EXPECT_EQ(modified.as_status(), Status::BadDeadbandFilterInvalid) << to_string(modified);
  write(mPlainId, 0.1);
  EXPECT_TRUE(await_value(0.1)) << "the refused modify left the item without a filter; " << reports();
  write(mPlainId, 0.2);
  EXPECT_TRUE(await_value(0.2)) << reports();
}

// A modify of a PercentDeadband item serves from the range it holds; once the EURange is not usable, a modify
// to a PercentDeadband is refused with Bad_DeadbandFilterInvalid.
// @relation(AC-SVR-DA-022-MODIFY-OF-PERCENT-ITEM-USES-HELD-RANGE, scope=function)
TEST_F(PercentDeadband, AModifyOfAPercentItemUsesItsHeldRangeAndRefusesAnUnusableOne)
{
  const uint32_t subscriptionId = subscribe();
  const uint32_t item = monitor(subscriptionId, mAnalogId, percent_deadband(10.0));
  ASSERT_NE(item, 0u);

  const auto first = modify(subscriptionId, item, percent_deadband(5.0));
  EXPECT_TRUE(first.is_good()) << to_string(first);
  write(mAnalogId, 4.0);
  observe();
  write(mAnalogId, 7.0);
  EXPECT_TRUE(await_value(7.0)) << "a change of 7 is above the deadband of 5; " << reports();
  EXPECT_FALSE(reported(4.0)) << "a change of 4 is within the deadband of 5; " << reports();

  write_eu_range(50.0, 50.0);
  observe(300ms);
  const auto second = modify(subscriptionId, item, percent_deadband(2.0));
  EXPECT_EQ(second.as_status(), Status::BadDeadbandFilterInvalid) << to_string(second);
}
