// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Deleting a Subscription, by DeleteSubscriptions or by CloseSession with deleteSubscriptions TRUE, deletes
// its MonitoredItems (Part 4 5.13.8.1, 5.6.4.2), and a MonitoredItem is deleted in the namespace that
// monitors its Node only when that namespace is told: NR-4 release rule 1 (finding NRF-1). Two test
// namespaces record every monitoring handle they issue and every delete_monitoring call; the Subscriptions
// are created and deleted by a Client over the wire.

#include <gtest/gtest.h>

#include "compliance_helpers.h"
#include "monitoring_recording_namespace.h"
#include "subscription.h"

#include "ua_access_level_type.h"
#include "ua_create_monitored_items_request.h"
#include "ua_datatype_id.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_node_accessor.h"
#include "ua_to_string.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;
using ua::test::MonitoringRecordingNamespace;

namespace
{

std::vector<MonitoringHandle> sorted(std::vector<MonitoringHandle> handles)
{
  std::sort(handles.begin(), handles.end());
  return handles;
}

std::string text(const std::vector<MonitoringHandle>& handles)
{
  std::string out = "{";
  for (const auto handle : handles)
  {
    out += (out.size() > 1 ? ", " : "") + std::to_string(handle);
  }
  return out + "}";
}

bool wait_until(const std::function<bool()>& condition, std::chrono::milliseconds timeout = 5s)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!condition())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(5ms);
  }
  return true;
}

class MonitoringRelease : public ComplianceSecuredWithSession
{
protected:
  /// What one namespace had issued and been asked to release when a Subscription was created.
  struct Mark
  {
    std::size_t issued = 0;
    std::size_t calls = 0;
  };

  void SetUp() override
  {
    ComplianceSecuredWithSession::SetUp();
    auto addressSpace = mServer->address_space();
    mNamespaceA = MonitoringRecordingNamespace::create(
      "urn:test:monitoring-release:a", mServerThreadPool.get_executor(), 100);
    mNamespaceB = MonitoringRecordingNamespace::create(
      "urn:test:monitoring-release:b", mServerThreadPool.get_executor(), 300);
    mIndexA = addressSpace.add_namespace_sync(mNamespaceA);
    mIndexB = addressSpace.add_namespace_sync(mNamespaceB);
    for (const auto index : {mIndexA, mIndexB})
    {
      for (uint32_t i = 1; i <= 2; ++i)
      {
        auto node = addressSpace.create_node_sync(NodeId{index, i}, NodeClass::Variable);
        auto variable = node.as<VariableAccessor>();
        ASSERT_TRUE(variable.has_value());
        variable->set_browse_name(QualifiedName{index, "Value" + std::to_string(i)});
        variable->set_display_name(LocalizedText{"", "Value" + std::to_string(i)});
        variable->set_data_type(NodeId{DataTypeId::Double});
        variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
        variable->write_value_sync(double{0.0});
      }
    }
    grant_fixture_namespace_permissions(addressSpace);
  }

  /// Creates a Subscription on @p session with two items on namespace A and one on namespace B.
  uint32_t subscribe_to_both(client::Session& session)
  {
    const uint32_t subscriptionId = create_subscription(session, {.publishingInterval = 100.0});
    EXPECT_NE(subscriptionId, 0u);
    auto request = build_create_mi_request(subscriptionId, NodeId{mIndexA, 1u}, {.clientHandle = 1});
    auto second = build_create_mi_request(subscriptionId, NodeId{mIndexA, 2u}, {.clientHandle = 2});
    auto third = build_create_mi_request(subscriptionId, NodeId{mIndexB, 1u}, {.clientHandle = 3});
    request.items_to_create().push_back(std::move(second.items_to_create()[0]));
    request.items_to_create().push_back(std::move(third.items_to_create()[0]));
    auto response = session.monitored_items().try_create_monitored_items_sync(std::move(request));
    EXPECT_TRUE(response.is_good()) << to_string(response.status_code());
    if (response.is_good())
    {
      EXPECT_EQ(response.value().results().size(), 3u);
      for (const auto& result : response.value().results())
      {
        EXPECT_TRUE(result.status_code().is_good()) << to_string(result.status_code());
      }
    }
    return subscriptionId;
  }

  static Mark mark(const MonitoringRecordingNamespace& ns)
  {
    return Mark{ns.issued_handles().size(), ns.delete_calls().size()};
  }

  /// Asserts that @p ns, since @p before, was asked once to release exactly the handles it issued since then.
  static void expect_released_once_in_one_call(
    const MonitoringRecordingNamespace& ns, const Mark& before, const std::string& name)
  {
    const auto issued = ns.issued_handles();
    const std::vector<MonitoringHandle> issuedSince(
      issued.begin() + static_cast<std::ptrdiff_t>(before.issued), issued.end());
    ASSERT_FALSE(issuedSince.empty()) << "precondition: namespace " << name << " issued handles";
    const bool released = wait_until(
      [&ns, &before, &issuedSince]
      {
        const auto calls = ns.delete_calls();
        std::vector<MonitoringHandle> since;
        for (std::size_t i = before.calls; i < calls.size(); ++i)
        {
          since.insert(since.end(), calls[i].begin(), calls[i].end());
        }
        return sorted(since) == sorted(issuedSince);
      });
    const auto calls = ns.delete_calls();
    std::vector<MonitoringHandle> since;
    for (std::size_t i = before.calls; i < calls.size(); ++i)
    {
      since.insert(since.end(), calls[i].begin(), calls[i].end());
    }
    EXPECT_TRUE(released) << "namespace " << name << " issued " << text(issuedSince)
                          << " and was asked to release " << text(since);
    EXPECT_EQ(calls.size() - before.calls, 1u) << "namespace " << name << " was not called once";
  }

  std::shared_ptr<MonitoringRecordingNamespace> mNamespaceA;
  std::shared_ptr<MonitoringRecordingNamespace> mNamespaceB;
  uint16_t mIndexA = 0;
  uint16_t mIndexB = 0;
};

}  // namespace

// @relation(AC-SVR-SUB-GEN-124-DELETE-RELEASES-EVERY-NAMESPACES-MONITORING, scope=function)
TEST_F(MonitoringRelease, DeleteSubscriptionsReleasesEveryNamespacesHandles)
{
  const auto beforeA = mark(*mNamespaceA);
  const auto beforeB = mark(*mNamespaceB);
  const uint32_t subscriptionId = subscribe_to_both(*mSession);

  DeleteSubscriptionsRequest request;
  request.subscription_ids().push_back(subscriptionId);
  const auto response = mSession->subscriptions().delete_subscriptions_sync(std::move(request));
  ASSERT_EQ(response.results().size(), 1u);
  ASSERT_TRUE(response.results()[0].is_good()) << to_string(response.results()[0]);

  expect_released_once_in_one_call(*mNamespaceA, beforeA, "A");
  expect_released_once_in_one_call(*mNamespaceB, beforeB, "B");
}

// @relation(AC-SVR-SUB-GEN-124-DELETE-RELEASES-EVERY-NAMESPACES-MONITORING, scope=function)
TEST_F(MonitoringRelease, CloseSessionWithDeleteSubscriptionsReleasesHandles)
{
  auto second = mChannel->create_session_sync({.sessionName = "MonitoringReleaseSecond"});
  second.activate_sync();
  const auto beforeA = mark(*mNamespaceA);
  const auto beforeB = mark(*mNamespaceB);
  subscribe_to_both(second);

  second.close_sync(client::Session::CloseOptions{.deleteSubscriptions = true});

  expect_released_once_in_one_call(*mNamespaceA, beforeA, "A");
  expect_released_once_in_one_call(*mNamespaceB, beforeB, "B");
}

// CreateMonitoredItems and ModifyMonitoredItems call the namespace with the Session's locales, as every other
// service carrying Session context does (NR-8); the control is the Session's own ActivateSession locales.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-26-THE-MONITORING-CALLS-CARRY-THE-SESSIONS-LOCALES, scope=function)
TEST_F(MonitoringRelease, TheMonitoringCallsCarryTheSessionsLocales)
{
  auto second = mChannel->create_session_sync({.sessionName = "MonitoringLocales"});
  second.activate_sync(client::Session::ActivateConfig{.localeIds = {String{"de-DE"}, String{"en"}}});
  const std::vector<LocaleId> sessionLocales{LocaleId{"de-DE"}, LocaleId{"en"}};
  const auto createsBefore = mNamespaceA->create_locales().size();
  const auto modifiesBefore = mNamespaceA->modify_locales().size();

  const uint32_t subscriptionId = create_subscription(second, {.publishingInterval = 100.0});
  ASSERT_NE(subscriptionId, 0u);
  auto create = build_create_mi_request(subscriptionId, NodeId{mIndexA, 1u}, {.clientHandle = 1});
  auto created = second.monitored_items().try_create_monitored_items_sync(std::move(create));
  ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
  ASSERT_EQ(created.value().results().size(), 1u);
  ASSERT_TRUE(created.value().results()[0].status_code().is_good())
    << to_string(created.value().results()[0].status_code());

  MonitoringParameters parameters;
  parameters.client_handle() = 1;
  parameters.sampling_interval() = 250.0;
  parameters.queue_size() = 1;
  parameters.discard_oldest() = true;
  MonitoredItemModifyRequest modifyItem;
  modifyItem.monitored_item_id() = created.value().results()[0].monitored_item_id();
  modifyItem.requested_parameters() = std::move(parameters);
  ModifyMonitoredItemsRequest modify;
  modify.subscription_id() = subscriptionId;
  modify.timestamps_to_return() = TimestampsToReturn::Both;
  modify.items_to_modify().push_back(std::move(modifyItem));
  const auto modified = second.monitored_items().modify_monitored_items_sync(std::move(modify));
  ASSERT_EQ(modified.results().size(), 1u);
  ASSERT_TRUE(modified.results()[0].status_code().is_good())
    << to_string(modified.results()[0].status_code());

  const auto creates = mNamespaceA->create_locales();
  ASSERT_EQ(creates.size(), createsBefore + 1) << "namespace A was not asked to create the item once";
  EXPECT_EQ(creates.back(), sessionLocales)
    << "CreateMonitoredItems called the namespace without the locales";
  const auto modifies = mNamespaceA->modify_locales();
  ASSERT_EQ(modifies.size(), modifiesBefore + 1) << "namespace A was not asked to modify the item once";
  EXPECT_EQ(modifies.back(), sessionLocales)
    << "ModifyMonitoredItems called the namespace without the locales";

  second.close_sync(client::Session::CloseOptions{.deleteSubscriptions = true});
}
