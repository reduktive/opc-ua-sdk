// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Tests for HistoryServerCapabilities address space population (Phase 10).
///
/// Verifies that ServerModel::populate_history_capabilities() correctly aggregates
/// NamespaceHistoryDelegate::Capabilities from all registered namespace history delegates and writes
/// the results to the HistoryServerCapabilities properties in the address space.

#include <gtest/gtest.h>

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_namespace_history_delegate.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"
#include "ua_server.h"
#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include "ua_variable_id.h"
#include "ua_value_source.h"

#include <atomic>
#include <chrono>
#include <future>

#include "posting_writes_namespace.h"
#include "test_log_sink.h"
#include "test_utilities.h"

#include "test_components.h"
using namespace ua;
using namespace ua::server;

namespace
{

// ---------------------------------------------------------------------------
// Fake history delegate with configurable capabilities
// ---------------------------------------------------------------------------
class FakeHistoryDelegate : public NamespaceHistoryDelegate
{
public:
  explicit FakeHistoryDelegate(NamespaceHistoryDelegate::Capabilities caps) : mCaps(caps)
  {}

  NamespaceHistoryDelegate::Capabilities capabilities() const noexcept override
  {
    return mCaps;
  }

private:
  NamespaceHistoryDelegate::Capabilities mCaps;
};

// ---------------------------------------------------------------------------
// Test namespace that provides a configurable history delegate
// ---------------------------------------------------------------------------
class HistoryCapTestNamespace : public default_ns::Namespace
{
public:
  HistoryCapTestNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  void set_delegate(shared_ptr<NamespaceHistoryDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  shared_ptr<NamespaceHistoryDelegate> mDelegate;
};

// ---------------------------------------------------------------------------
// Helper: read a boolean capability from the address space
// ---------------------------------------------------------------------------
bool read_bool_capability(AddressSpace& addressSpace, VariableId variableId)
{
  auto node = addressSpace.find_node_sync(NodeId{variableId});
  auto variable = node.as<VariableAccessor>();
  auto dataValue = variable->read_value_sync();
  return dataValue.value().as<bool>();
}

// ---------------------------------------------------------------------------
// Helper: read a uint32 capability from the address space
// ---------------------------------------------------------------------------
uint32_t read_uint32_capability(AddressSpace& addressSpace, VariableId variableId)
{
  auto node = addressSpace.find_node_sync(NodeId{variableId});
  auto variable = node.as<VariableAccessor>();
  auto dataValue = variable->read_value_sync();
  return dataValue.value().as<uint32_t>();
}

uint8_t read_uint8_capability(AddressSpace& addressSpace, VariableId variableId)
{
  auto node = addressSpace.find_node_sync(NodeId{variableId});
  auto variable = node.as<VariableAccessor>();
  auto dataValue = variable->read_value_sync();
  return dataValue.value().as<uint8_t>();
}

// ---------------------------------------------------------------------------
// Test harness: creates a server, optionally adds namespaces, starts it
// ---------------------------------------------------------------------------
struct HistoryCapTestHarness
{
  boost::asio::thread_pool threadPool;
  std::optional<Server> server;

  ~HistoryCapTestHarness()
  {
    if (server)
    {
      (void)server->try_shutdown_sync();
      server.reset();
    }
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  void create_server(ServerConfig serverConfiguration = {})
  {
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = std::move(serverConfiguration)};

    server.emplace(Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()}));
  }

  void add_namespace_with_delegate(const std::string& uri, NamespaceHistoryDelegate::Capabilities caps)
  {
    auto ns = make_shared<HistoryCapTestNamespace>(uri, threadPool.get_executor());
    ns->set_delegate(make_shared<FakeHistoryDelegate>(caps));
    server->address_space().add_namespace_sync(ns);
  }

  void add_namespace_without_delegate(const std::string& uri)
  {
    auto ns = make_shared<HistoryCapTestNamespace>(uri, threadPool.get_executor());
    server->address_space().add_namespace_sync(ns);
  }

  void start()
  {
    server->start_sync();
  }

  AddressSpace address_space()
  {
    return server->address_space();
  }
};

}  // namespace

// ---------------------------------------------------------------------------
// Test 1: No history delegate registered -> all capabilities are false
// ---------------------------------------------------------------------------
// @relation(SVR-HIST-CAP-001, SVR-HIST-CAP-002, scope=function)
TEST(HistoryServerCapabilities, NoHistoryDelegate_AllCapsFalse)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.start();

  auto as = harness.address_space();

  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryDataCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_InsertDataCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_ReplaceDataCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_UpdateDataCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteRawCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteAtTimeCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_InsertEventCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_ReplaceEventCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_UpdateEventCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteEventCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_InsertAnnotationCapability));
}

// ---------------------------------------------------------------------------
// Test 2: Delegate with read_raw=true -> AccessHistoryDataCapability is true
// ---------------------------------------------------------------------------
// @relation(SVR-HIST-CAP-002, scope=function)
TEST(HistoryServerCapabilities, WithDelegate_AccessHistoryDataTrue)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_with_delegate(
    "urn:test:history-caps-1", NamespaceHistoryDelegate::Capabilities{.readRaw = true});
  harness.start();

  auto as = harness.address_space();

  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryDataCapability));
}

// ---------------------------------------------------------------------------
// Test 3: Delegate capabilities are correctly reflected in the address space
// ---------------------------------------------------------------------------
TEST(HistoryServerCapabilities, DelegateCapabilitiesReflected)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_with_delegate("urn:test:history-caps-2",
    NamespaceHistoryDelegate::Capabilities{.readRaw = true, .updateData = true, .deleteRaw = true});
  harness.start();

  auto as = harness.address_space();

  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryDataCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_InsertDataCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_ReplaceDataCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_UpdateDataCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteRawCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteAtTimeCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteEventCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_ServerTimestampSupported));
}

// ---------------------------------------------------------------------------
// Test 4: Multiple namespaces -> capabilities are OR-aggregated
// ---------------------------------------------------------------------------
// @relation(SVR-HIST-CAP-002, scope=function)
TEST(HistoryServerCapabilities, MultipleNamespacesAggregated)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_with_delegate(
    "urn:test:history-caps-3a", NamespaceHistoryDelegate::Capabilities{.readRaw = true, .deleteRaw = true});
  harness.add_namespace_with_delegate("urn:test:history-caps-3b",
    NamespaceHistoryDelegate::Capabilities{.readRaw = true, .updateData = true, .deleteAtTime = true});
  harness.start();

  auto as = harness.address_space();

  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryDataCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteRawCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_UpdateDataCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteAtTimeCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_InsertDataCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_ReplaceDataCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteEventCapability));
}

// ---------------------------------------------------------------------------
// Test 5: MaxReturnDataValues and MaxReturnEventValues default to 0
// ---------------------------------------------------------------------------
// RATIFIED EXPECTATION CHANGE (DEF-6): the defaults were 0 (unlimited); a finite default of 10000
// bounds what one HistoryRead can materialise. 0 stays a legal, explicit "unlimited".
// @verifies AC-SVR-HIST-CAP-004-DEFAULT-RETURN-LIMITS-ARE-FINITE
TEST(HistoryServerCapabilities, MaxReturnValuesDefaultToTenThousand)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_with_delegate(
    "urn:test:history-caps-4", NamespaceHistoryDelegate::Capabilities{.readRaw = true});
  harness.start();

  auto as = harness.address_space();

  EXPECT_EQ(read_uint32_capability(as, VariableId::HistoryServerCapabilities_MaxReturnDataValues), 10000u);
  EXPECT_EQ(read_uint32_capability(as, VariableId::HistoryServerCapabilities_MaxReturnEventValues), 10000u);
}

// ---------------------------------------------------------------------------
// Test 6: ServerTimestampSupported is always true (even with no delegates)
// ---------------------------------------------------------------------------
TEST(HistoryServerCapabilities, ServerTimestampSupportedAlwaysTrue)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.start();

  auto as = harness.address_space();

  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_ServerTimestampSupported));
}

// ---------------------------------------------------------------------------
// Test 7: Namespace without delegate does not contribute to capabilities
// ---------------------------------------------------------------------------
TEST(HistoryServerCapabilities, NamespaceWithoutDelegateIgnored)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_without_delegate("urn:test:no-delegate");
  harness.start();

  auto as = harness.address_space();

  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryDataCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_InsertDataCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteRawCapability));
}

// ---------------------------------------------------------------------------
// Test 8: Event capabilities (InsertEvent, ReplaceEvent, UpdateEvent are always false;
//         DeleteEvent reflects aggregated delete_events)
// ---------------------------------------------------------------------------
// @relation(SVR-HIST-CAP-003, scope=function)
TEST(HistoryServerCapabilities, EventCapabilities)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_with_delegate("urn:test:history-caps-events",
    NamespaceHistoryDelegate::Capabilities{.readEvents = true, .deleteEvents = true});
  harness.start();

  auto as = harness.address_space();

  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability));
  EXPECT_TRUE(read_bool_capability(as, VariableId::HistoryServerCapabilities_DeleteEventCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_InsertEventCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_ReplaceEventCapability));
  EXPECT_FALSE(read_bool_capability(as, VariableId::HistoryServerCapabilities_UpdateEventCapability));
}

// ---------------------------------------------------------------------------
// AggregateFunctions advertising: the supported aggregates are Organized into
// the AggregateFunctions folders only when a delegate supplies raw history (the
// turnkey calculator path). Gated on read_raw - see write_history_capabilities.
// ---------------------------------------------------------------------------

namespace
{
bool folder_organizes(AddressSpace& addressSpace, ObjectId folderId, uint32_t targetNumericId)
{
  auto folder = addressSpace.find_node_sync(NodeId{folderId});
  for (const auto& reference : folder.get_references_sync())
  {
    if (reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::Organizes} &&
        reference.target_id().node_id() == NodeId{targetNumericId})
      return true;
  }
  return false;
}
}  // namespace

// Covers SVR-HIST-CAP-013 (coverage-audit retag).
TEST(HistoryServerCapabilities, AggregateFunctionsAdvertisedWhenReadRaw)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  NamespaceHistoryDelegate::Capabilities caps;
  caps.readRaw = true;
  harness.add_namespace_with_delegate("uri://agg-advertise-ns", caps);
  harness.start();

  auto as = harness.address_space();

  // The aggregate objects were imported by id (orphans in the NodeSet).
  EXPECT_TRUE(
    as.try_find_node_sync(NodeId{static_cast<uint32_t>(ObjectId::AggregateFunction_Count)}).is_good());

  // Both AggregateFunctions folders Organize the supported set (Count, Average).
  for (auto folderId : {ObjectId::HistoryServerCapabilities_AggregateFunctions,
         ObjectId::Server_ServerCapabilities_AggregateFunctions})
  {
    EXPECT_TRUE(folder_organizes(as, folderId, static_cast<uint32_t>(ObjectId::AggregateFunction_Count)))
      << "folder " << static_cast<uint32_t>(folderId) << " should Organize Count";
    EXPECT_TRUE(folder_organizes(as, folderId, static_cast<uint32_t>(ObjectId::AggregateFunction_Average)))
      << "folder " << static_cast<uint32_t>(folderId) << " should Organize Average";
  }
}

TEST(HistoryServerCapabilities, AggregateFunctionsNotAdvertisedWithoutReadRaw)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  // A delegate that supports events but NOT raw history => no turnkey aggregation.
  NamespaceHistoryDelegate::Capabilities caps;
  caps.readEvents = true;
  harness.add_namespace_with_delegate("uri://agg-no-raw-ns", caps);
  harness.start();

  auto as = harness.address_space();

  EXPECT_FALSE(folder_organizes(as,
    ObjectId::HistoryServerCapabilities_AggregateFunctions,
    static_cast<uint32_t>(ObjectId::AggregateFunction_Count)))
    << "no read_raw delegate => no aggregate advertising";
}

// @relation(AC-SVR-HIST-CAP-004-DATA-LIMIT, scope=function)
// @relation(AC-SVR-HIST-CAP-005-EVENT-LIMIT, scope=function)
TEST(HistoryServerCapabilitiesRestored, ConfiguredReturnLimitsPublishedIndependently)
{
  ServerConfig configuration;
  configuration.historyConfiguration.maxReturnDataValues = 17;
  configuration.historyConfiguration.maxReturnEventValues = 29;

  HistoryCapTestHarness harness;
  harness.create_server(std::move(configuration));
  harness.start();

  auto addressSpace = harness.address_space();
  EXPECT_EQ(
    read_uint32_capability(addressSpace, VariableId::HistoryServerCapabilities_MaxReturnDataValues), 17u);
  EXPECT_EQ(
    read_uint32_capability(addressSpace, VariableId::HistoryServerCapabilities_MaxReturnEventValues), 29u);
}

// @relation(AC-SVR-HIST-CAP-006-INSERT-DATA, scope=function)
// @relation(AC-SVR-HIST-CAP-007-REPLACE-DATA, scope=function)
// @relation(AC-SVR-HIST-CAP-008-UPDATE-DATA, scope=function)
TEST(HistoryServerCapabilitiesRestored, DataMutationCapabilitiesReflectDelegateSupport)
{
  {
    HistoryCapTestHarness supported;
    supported.create_server();
    supported.add_namespace_with_delegate(
      "urn:test:history-caps-data-update", NamespaceHistoryDelegate::Capabilities{.updateData = true});
    supported.start();

    auto addressSpace = supported.address_space();
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_InsertDataCapability));
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_ReplaceDataCapability));
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_UpdateDataCapability));
  }

  {
    HistoryCapTestHarness unsupported;
    unsupported.create_server();
    unsupported.add_namespace_with_delegate(
      "urn:test:history-caps-data-read-only", NamespaceHistoryDelegate::Capabilities{.readRaw = true});
    unsupported.start();

    auto addressSpace = unsupported.address_space();
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_InsertDataCapability));
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_ReplaceDataCapability));
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_UpdateDataCapability));
  }
}

// @relation(AC-SVR-HIST-CAP-009-DELETE-RAW, scope=function)
// @relation(AC-SVR-HIST-CAP-010-DELETE-AT-TIME, scope=function)
TEST(HistoryServerCapabilitiesRestored, DeleteCapabilitiesRemainIndependent)
{
  {
    HistoryCapTestHarness rawOnly;
    rawOnly.create_server();
    rawOnly.add_namespace_with_delegate("urn:test:history-caps-delete-raw",
      NamespaceHistoryDelegate::Capabilities{.readRaw = true, .deleteRaw = true});
    rawOnly.start();

    auto addressSpace = rawOnly.address_space();
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_DeleteRawCapability));
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_DeleteAtTimeCapability));
  }

  {
    HistoryCapTestHarness atTimeOnly;
    atTimeOnly.create_server();
    atTimeOnly.add_namespace_with_delegate("urn:test:history-caps-delete-at-time",
      NamespaceHistoryDelegate::Capabilities{.readRaw = true, .deleteAtTime = true});
    atTimeOnly.start();

    auto addressSpace = atTimeOnly.address_space();
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_DeleteRawCapability));
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_DeleteAtTimeCapability));
  }
}

// @relation(AC-SVR-HIST-CAP-011-EVENT-MUTATION, scope=function)
// @relation(AC-SVR-HIST-CAP-012-INSERT-ANNOTATION, scope=function)
TEST(HistoryServerCapabilitiesRestored, EventAndAnnotationCapabilitiesRemainIndependent)
{
  {
    HistoryCapTestHarness eventUpdateOnly;
    eventUpdateOnly.create_server();
    eventUpdateOnly.add_namespace_with_delegate("urn:test:history-caps-event-update",
      NamespaceHistoryDelegate::Capabilities{.readEvents = true, .updateEvent = true});
    eventUpdateOnly.start();

    auto addressSpace = eventUpdateOnly.address_space();
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_InsertEventCapability));
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_ReplaceEventCapability));
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_UpdateEventCapability));
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_DeleteEventCapability));
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_InsertAnnotationCapability));
  }

  {
    HistoryCapTestHarness deleteAndAnnotate;
    deleteAndAnnotate.create_server();
    deleteAndAnnotate.add_namespace_with_delegate("urn:test:history-caps-event-delete-annotation",
      NamespaceHistoryDelegate::Capabilities{
        .readEvents = true, .insertAnnotation = true, .deleteEvents = true});
    deleteAndAnnotate.start();

    auto addressSpace = deleteAndAnnotate.address_space();
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_InsertEventCapability));
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_ReplaceEventCapability));
    EXPECT_FALSE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_UpdateEventCapability));
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_DeleteEventCapability));
    EXPECT_TRUE(
      read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_InsertAnnotationCapability));
  }
}

// @relation(AC-SVR-HIST-CAP-013-AGGREGATE-FOLDERS, scope=function)
TEST(HistoryServerCapabilitiesRestored, AggregateFunctionsPublishedUnderBothFoldersOnlyWhenUsable)
{
  constexpr auto countId = static_cast<uint32_t>(ObjectId::AggregateFunction_Count);
  constexpr auto averageId = static_cast<uint32_t>(ObjectId::AggregateFunction_Average);

  {
    HistoryCapTestHarness supported;
    supported.create_server();
    supported.add_namespace_with_delegate(
      "urn:test:history-caps-aggregate", NamespaceHistoryDelegate::Capabilities{.readRaw = true});
    supported.start();

    auto addressSpace = supported.address_space();
    for (auto folderId : {ObjectId::Server_ServerCapabilities_AggregateFunctions,
           ObjectId::HistoryServerCapabilities_AggregateFunctions})
    {
      EXPECT_TRUE(folder_organizes(addressSpace, folderId, countId));
      EXPECT_TRUE(folder_organizes(addressSpace, folderId, averageId));
    }
  }

  {
    HistoryCapTestHarness unsupported;
    unsupported.create_server();
    unsupported.add_namespace_with_delegate(
      "urn:test:history-caps-events-only", NamespaceHistoryDelegate::Capabilities{.readEvents = true});
    unsupported.start();

    auto addressSpace = unsupported.address_space();
    EXPECT_FALSE(
      folder_organizes(addressSpace, ObjectId::HistoryServerCapabilities_AggregateFunctions, countId));
    EXPECT_FALSE(
      folder_organizes(addressSpace, ObjectId::HistoryServerCapabilities_AggregateFunctions, averageId));
  }
}

// @relation(AC-SVR-HIST-CAP-014-SERVER-TIMESTAMP, scope=function)
TEST(HistoryServerCapabilitiesRestored, ServerTimestampSupportIsPublished)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.start();

  auto addressSpace = harness.address_space();
  ASSERT_TRUE(
    addressSpace.try_find_node_sync(NodeId{VariableId::HistoryServerCapabilities_ServerTimestampSupported})
      .is_good());
  EXPECT_TRUE(
    read_bool_capability(addressSpace, VariableId::HistoryServerCapabilities_ServerTimestampSupported));
}

// @relation(AC-SVR-HIST-AGG-001-MODEL-DEFAULTS, scope=function)
TEST(HistoryServerCapabilitiesRestored, AggregateConfigurationModelDefaultsAreStandard)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_with_delegate(
    "urn:test:history-aggregate-defaults", NamespaceHistoryDelegate::Capabilities{.readRaw = true});
  harness.start();

  auto addressSpace = harness.address_space();
  ASSERT_TRUE(addressSpace.try_find_node_sync(NodeId{ObjectId::DefaultHAConfiguration}).is_good());
  EXPECT_TRUE(folder_organizes(
    addressSpace, ObjectId::Server, static_cast<uint32_t>(ObjectId::DefaultHAConfiguration)));
  EXPECT_TRUE(read_bool_capability(
    addressSpace, VariableId::DefaultHAConfiguration_AggregateConfiguration_TreatUncertainAsBad));
  EXPECT_EQ(read_uint8_capability(
              addressSpace, VariableId::DefaultHAConfiguration_AggregateConfiguration_PercentDataBad),
    100u);
  EXPECT_EQ(read_uint8_capability(
              addressSpace, VariableId::DefaultHAConfiguration_AggregateConfiguration_PercentDataGood),
    100u);
  EXPECT_FALSE(read_bool_capability(
    addressSpace, VariableId::DefaultHAConfiguration_AggregateConfiguration_UseSlopedExtrapolation));
}

// @relation(AC-SVR-HIST-CAP-015-AGGREGATE-CONFIGURATION-MANDATORY, scope=function)
TEST(
  HistoryServerCapabilitiesRestored, HistoricalDataConfigurationExposesMandatoryAggregateConfigurationObject)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_with_delegate("urn:test:history-mandatory-aggregate-configuration",
    NamespaceHistoryDelegate::Capabilities{.readRaw = true});
  harness.start();

  auto addressSpace = harness.address_space();
  const NodeId configurationId{ObjectId::DefaultHAConfiguration};
  const NodeId aggregateConfigurationId{ObjectId::DefaultHAConfiguration_AggregateConfiguration};

  ASSERT_TRUE(addressSpace.try_find_node_sync(configurationId).is_good());
  const auto configuration = addressSpace.find_node_sync(configurationId);
  bool ownsAggregateConfiguration = false;
  for (const auto& reference : configuration.get_references_sync())
  {
    if (reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasComponent} &&
        reference.target_id().node_id() == aggregateConfigurationId)
    {
      ownsAggregateConfiguration = true;
      break;
    }
  }
  EXPECT_TRUE(ownsAggregateConfiguration)
    << "HistoricalDataConfigurationType requires a forward HasComponent AggregateConfiguration Object";

  ASSERT_TRUE(addressSpace.try_find_node_sync(aggregateConfigurationId).is_good());
  const auto aggregateConfiguration = addressSpace.find_node_sync(aggregateConfigurationId);
  EXPECT_EQ(aggregateConfiguration.get_browse_name(), QualifiedName(0, "AggregateConfiguration"));

  bool hasExactTypeDefinition = false;
  for (const auto& reference : aggregateConfiguration.get_references_sync())
  {
    if (reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition} &&
        reference.target_id().node_id() == NodeId{ObjectTypeId::AggregateConfigurationType})
    {
      hasExactTypeDefinition = true;
      break;
    }
  }
  EXPECT_TRUE(hasExactTypeDefinition)
    << "AggregateConfiguration must have TypeDefinition AggregateConfigurationType";
}

// ---------------------------------------------------------------------------
// Part 11 5.4 / Part 13 4.2.2.1: on a server supporting Historical Access the
// HistoryServerCapabilities Object must be discoverable by browsing
// Server.ServerCapabilities - a HasComponent Reference from ServerCapabilities to an Object whose
// TypeDefinition is HistoryServerCapabilitiesType. A plausible implementation gets this wrong
// because writing the capability Variables (which every other test here reaches by absolute
// VariableId, never by browsing) leaves the container itself unreachable: the standard NodeSet
// declares this edge only as the inverse HasComponent stored on HistoryServerCapabilities, and
// nothing synthesises the forward edge on ServerCapabilities, so a client that walks the
// ServerCapabilities Object - the only route it has - never finds the capability surface.
// @verifies AC-SVR-HIST-CAP-001-CAPABILITIES-OBJECT
TEST(HistoryServerCapabilities, CapabilitiesObjectIsReferencedFromServerCapabilities)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  // A server that supports Historical Access: a namespace whose delegate serves raw history.
  harness.add_namespace_with_delegate(
    "urn:test:history-caps-object", NamespaceHistoryDelegate::Capabilities{.readRaw = true});
  harness.start();

  auto as = harness.address_space();

  // First conjunct: ServerCapabilities HasComponent the HistoryServerCapabilities Object.
  ASSERT_TRUE(as.try_find_node_sync(NodeId{ObjectId::Server_ServerCapabilities}).is_good())
    << "Server.ServerCapabilities is missing from the address space";
  auto serverCapabilities = as.find_node_sync(NodeId{ObjectId::Server_ServerCapabilities});
  auto serverCapabilityReferences = serverCapabilities.get_references_sync();
  ASSERT_FALSE(serverCapabilityReferences.empty()) << "Server.ServerCapabilities has no References at all";

  const auto historyCapabilitiesId = NodeId{ObjectId::HistoryServerCapabilities};
  bool referencedFromServerCapabilities = false;
  for (const auto& reference : serverCapabilityReferences)
  {
    if (reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasComponent} &&
        reference.target_id().node_id() == historyCapabilitiesId)
    {
      referencedFromServerCapabilities = true;
      break;
    }
  }
  EXPECT_TRUE(referencedFromServerCapabilities)
    << "browsing Server.ServerCapabilities must reach the HistoryServerCapabilities Object";

  // Second conjunct: the Object so referenced is of type HistoryServerCapabilitiesType.
  ASSERT_TRUE(as.try_find_node_sync(historyCapabilitiesId).is_good())
    << "the HistoryServerCapabilities Object is missing from the address space";
  auto historyCapabilities = as.find_node_sync(historyCapabilitiesId);
  auto historyCapabilityReferences = historyCapabilities.get_references_sync();
  ASSERT_FALSE(historyCapabilityReferences.empty())
    << "the HistoryServerCapabilities Object has no References at all";

  bool typedAsHistoryServerCapabilitiesType = false;
  for (const auto& reference : historyCapabilityReferences)
  {
    if (reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasTypeDefinition} &&
        reference.target_id().node_id() == NodeId{ObjectTypeId::HistoryServerCapabilitiesType})
    {
      typedAsHistoryServerCapabilitiesType = true;
      break;
    }
  }
  EXPECT_TRUE(typedAsHistoryServerCapabilitiesType)
    << "the referenced Object must have TypeDefinition HistoryServerCapabilitiesType";
}

// Start populates HistoryServerCapabilities from the start continuation, which runs on the Server's
// executor. Each capability is written through whatever serves its Variable, which may answer by
// posting to that executor. On a one-thread executor a blocking write waits there for an answer that can
// only run there and the start never completes; the awaited population must let it complete, and the
// Variable must still receive its value.
// @relation(SVR-HIST-CAP-002, scope=function)
TEST(HistoryServerCapabilities, StartCompletesWhenACapabilityWriteIsAnsweredByPosting)
{
  ua::test::OneThreadExecutor executor;
  CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
    .application = test_utils::create_test_config(),
    .server = ServerConfig{}};
  auto server = Server::create(executor.executor(),
    std::move(cfg),
    ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
  auto ns = make_shared<HistoryCapTestNamespace>("urn:test:history-caps-posting", executor.executor());
  ns->set_delegate(make_shared<FakeHistoryDelegate>(NamespaceHistoryDelegate::Capabilities{.readRaw = true}));
  server.address_space().add_namespace_sync(ns);

  auto addressSpace = server.address_space();
  auto capability = addressSpace.try_find_node_sync(
    NodeId{VariableId::HistoryServerCapabilities_AccessHistoryDataCapability});
  ASSERT_TRUE(capability.is_good());
  auto* source = capability.value()->external_value_source();
  ASSERT_NE(source, nullptr);
  auto written = std::make_shared<std::atomic<int>>(0);
  auto advertised = std::make_shared<std::atomic<bool>>(false);
  ASSERT_TRUE(
    source
      ->set_value_source(make_value_source([](const ValueSource::ReadContext&,
                                             const Node&,
                                             const ReadValueId&,
                                             std::function<void(DataValueResult)>
                                               complete) { complete(DataValue{}); },
        [answerExecutor = executor.executor(), written, advertised](const ValueSource::WriteContext&,
          const Node&,
          const WriteValue& write,
          std::function<void(ValueSource::WriteResult)>
            complete)
        {
          ++*written;
          if (const auto* flag = write.value().value().try_as<bool>())
            *advertised = *flag;
          boost::asio::post(
            answerExecutor, [complete = std::move(complete)]() mutable { complete(ValueSource::Written{}); });
        }))
      .is_good());

  auto started = std::make_shared<std::promise<VoidResult>>();
  auto future = started->get_future();
  server.start_async([started](VoidResult result) { started->set_value(std::move(result)); });
  ASSERT_EQ(future.wait_for(std::chrono::seconds{20}), std::future_status::ready)
    << "the start blocked the thread its capability Variable's write answers on";
  const auto result = future.get();
  EXPECT_TRUE(result.is_good()) << result.status_code().as_uint32();
  EXPECT_EQ(written->load(), 1);
  EXPECT_TRUE(advertised->load()) << "AccessHistoryDataCapability was not advertised";

  (void)server.try_shutdown_sync();
}

// Part 3 section 5.3.2 recommends instantiating hierarchical References in both directions; NR-30 makes the
// SDK add both halves of the hierarchical References it adds itself. With raw history read by a namespace,
// the server model Organizes the supported aggregate functions under three AggregateFunctions folders. Each
// folder's forward Organizes is the control; each aggregate function must hold the inverse Organizes to that
// folder.
// @relation(AC-SVR-ADDRSP-261-AGGREGATE-FOLDERS-BIDIRECTIONAL, scope=function)
TEST(ServerModelAggregateFolders, EachAggregateFunctionHoldsTheInverseOrganizesToItsFolder)
{
  HistoryCapTestHarness harness;
  harness.create_server();
  harness.add_namespace_with_delegate(
    "urn:test:history-aggregate-folders-inverse", NamespaceHistoryDelegate::Capabilities{.readRaw = true});
  harness.start();
  auto addressSpace = harness.address_space();
  const NodeId organizes{ReferenceTypeId::Organizes};

  for (const auto folderId : {ObjectId::Server_ServerCapabilities_AggregateFunctions,
         ObjectId::HistoryServerCapabilities_AggregateFunctions,
         ObjectId::DefaultHAConfiguration_AggregateFunctions})
  {
    const NodeId folderNodeId{folderId};
    auto folder = addressSpace.try_find_node_sync(folderNodeId);
    ASSERT_TRUE(folder.is_good()) << "the folder " << to_string(folderNodeId)
                                  << " is not in the address space";
    std::vector<NodeId> functions;
    for (const auto& reference : folder.value().get_references_sync())
    {
      if (reference.is_forward() && reference.type_id() == organizes)
        functions.push_back(reference.target_id().node_id());
    }
    ASSERT_FALSE(functions.empty()) << "the folder " << to_string(folderNodeId)
                                    << " organises no aggregate function";

    for (const auto& functionId : functions)
    {
      auto function = addressSpace.try_find_node_sync(functionId);
      ASSERT_TRUE(function.is_good()) << to_string(functionId);
      bool holdsTheInverse = false;
      for (const auto& reference : function.value().get_references_sync())
      {
        holdsTheInverse = holdsTheInverse || (!reference.is_forward() && reference.type_id() == organizes &&
                                               reference.target_id().node_id() == folderNodeId);
      }
      EXPECT_TRUE(holdsTheInverse) << "the aggregate function " << to_string(functionId)
                                   << " holds no inverse Organizes to the folder " << to_string(folderNodeId);
    }
  }
}
