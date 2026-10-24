// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A Condition binds the value readers of its Variables through the Node's probe, not by casting the
/// Node (COMP-ADDRSP-ACCESSOR-ROUTE-04).
///
/// The Condition's Nodes are held by a namespace whose Nodes wrap in-memory Nodes and give the wrapped
/// Node's value source through `external_value_source()` without deriving from `ExternalValueSource`.
/// On a namespace whose Nodes give no value source, the Condition fails to initialise (DL-115 (8), item 6).

#include "ua_alarm_condition_logic.h"
#include "ua_application_configuration.h"
#include "ua_base_event.h"
#include "ua_condition_instance.h"
#include "ua_data_type_registration.h"
#include "ua_data_value.h"
#include "ua_encoding_limits.h"
#include "ua_file_stream.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_objecttype_id.h"
#include "ua_sinks.h"
#include "ua_status.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "posting_writes_namespace.h"
#include "unit/address_space/namespace_conformance/described_conformance_namespace.h"
#include "test_utilities.h"

using namespace ua;

namespace
{

/// Gives each emitted Event an EventId, as the EventBus does, and keeps nothing.
class EventIdAssigningSink final : public EventSink
{
public:
  void emit(BaseEvent& event) override
  {
    const auto emitted = ++mEmitted;
    if (event.eventId.empty())
    {
      event.eventId = ByteString{std::vector<uint8_t>{static_cast<uint8_t>(emitted)}};
    }
  }

private:
  std::atomic<int> mEmitted{0};
};

/// Loads namespace 0 into @p addressSpace from NodeSet2.xml.
void import_namespace_zero(AddressSpace& addressSpace)
{
  const auto limits = make_encoding_limits(ApplicationConfig::load_default());
  StructureFactory structureFactory;
  auto lookup = namespace_array_utils::get_index_lookup_function(addressSpace);
  const CodecNamespaceContext codecContext{std::move(lookup), {}, {}, {}};
  register_ua_data_types_with_factory(codecContext, &structureFactory, &structureFactory);
  FileStream inputStream{"NodeSet2.xml"};
  inputStream.open_for_read();
  auto nodeSets = xml::nodeset::Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    xml::nodeset::Parser::GetDependentModelCallback{});
  auto importer = xml::nodeset::ImportEngine::create(limits, addressSpace, nodeSets, {});
  importer->import_all_sync({}, {});
}

/// The forward child of @p parent whose BrowseName is @p name, or a null NodeId.
NodeId child_named(AddressSpace& addressSpace, const NodeId& parent, const std::string& name)
{
  auto found = addressSpace.try_find_node_sync(parent);
  if (found.is_bad())
  {
    return NodeId{};
  }
  for (const auto& reference : found.value().get_references_sync())
  {
    if (!reference.is_forward() || reference.is_remote())
    {
      continue;
    }
    auto child = addressSpace.try_find_node_sync(reference.target_id().node_id());
    if (child.is_good() && std::string{child.value().get_browse_name().name()} == name)
    {
      return reference.target_id().node_id();
    }
  }
  return NodeId{};
}

}  // namespace

// Severity is bound as a DirectChild through ConditionInstance's installReadHandler, the binding the
// criterion names (ua_condition_instance.cpp:3172).
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-04-A-CONDITION-BINDS-ITS-VALUE-READERS-THROUGH-THE-PROBE, scope=function)
TEST(ConditionSourceProbe, AConditionOnASourceOfAnotherNamespaceBindsThroughTheProbe)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("uri:test:condition-source-probe", pool.get_executor());
    import_namespace_zero(addressSpace);
    auto probing =
      ua::test::PostingWritesNamespace::create("urn:test:condition-source-probe", pool.get_executor());
    const auto index = addressSpace.try_add_namespace_sync(probing);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    const uint16_t s = index.value();

    const NodeId sourceId{s, 100u};
    auto source = addressSpace.try_create_node_sync(sourceId, NodeClass::Object, {});
    ASSERT_TRUE(source.is_good()) << to_string(source.status_code());
    source.value().set_browse_name(QualifiedName{s, "ProbeSource"});

    auto sink = std::make_shared<EventIdAssigningSink>();
    auto instance = ConditionInstance::create(pool.get_executor(),
      std::make_unique<AlarmConditionLogic>(),
      NodeId{s, 1000u},
      sourceId,
      String{"ProbeSource"},
      sink,
      addressSpace,
      NodeId{ObjectTypeId::AlarmConditionType});
    const auto initialized = instance->try_initialize_sync();
    ASSERT_TRUE(initialized.is_good()) << to_string(initialized.status_code());
    const auto enabled = instance->try_enable_sync();
    ASSERT_TRUE(enabled.is_good()) << to_string(enabled.status_code());
    const auto activated = instance->try_activate_sync(500);
    ASSERT_TRUE(activated.is_good()) << to_string(activated.status_code());

    const auto severityId = child_named(addressSpace, instance->condition_id(), "Severity");
    ASSERT_FALSE(severityId.is_null()) << "the Condition has no Severity Variable";
    ASSERT_EQ(severityId.namespace_index(), s)
      << "the Severity Variable is not held by the probing namespace";
    auto severity = addressSpace.try_find_sync<VariableAccessor>(severityId);
    ASSERT_TRUE(severity.is_good()) << to_string(severity.status_code());
    const auto read = severity.value().try_read_value_sync();
    ASSERT_TRUE(read.is_good()) << to_string(read.status_code());
    const auto* value = read.value().value().try_as<uint16_t>();
    ASSERT_NE(value, nullptr) << "the Severity read answered " << to_string(read.value().value())
                              << ", not a UInt16";
    EXPECT_EQ(*value, 500);
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// A Variable whose value reader the Condition bound is deleted, as a client's DeleteNodes can, while the
// Condition lives. Every state change afterwards tells the bound Variables that their Values may have
// changed; that must not reach the deleted Node.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-04-A-STATE-CHANGE-DOES-NOT-REACH-A-DELETED-BOUND-VARIABLE, scope=function)
TEST(ConditionSourceProbe, AStateChangeAfterABoundVariableIsDeletedDoesNotReachTheDeletedNode)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace =
      AddressSpace::create("uri:test:condition-bound-variable-deleted", pool.get_executor());
    import_namespace_zero(addressSpace);

    const NodeId sourceId{1, 100u};
    auto source = addressSpace.try_create_node_sync(sourceId, NodeClass::Object, {});
    ASSERT_TRUE(source.is_good()) << to_string(source.status_code());
    source.value().set_browse_name(QualifiedName{1, "DeletedVariableSource"});

    auto sink = std::make_shared<EventIdAssigningSink>();
    auto instance = ConditionInstance::create(pool.get_executor(),
      std::make_unique<AlarmConditionLogic>(),
      NodeId{1, 1000u},
      sourceId,
      String{"DeletedVariableSource"},
      sink,
      addressSpace,
      NodeId{ObjectTypeId::AlarmConditionType});
    const auto initialized = instance->try_initialize_sync();
    ASSERT_TRUE(initialized.is_good()) << to_string(initialized.status_code());
    const auto enabled = instance->try_enable_sync();
    ASSERT_TRUE(enabled.is_good()) << to_string(enabled.status_code());
    const auto activated = instance->try_activate_sync(500);
    ASSERT_TRUE(activated.is_good()) << to_string(activated.status_code());

    const auto severityId = child_named(addressSpace, instance->condition_id(), "Severity");
    ASSERT_FALSE(severityId.is_null()) << "the Condition has no Severity Variable";
    const auto deleted = addressSpace.try_delete_node_sync(severityId, false);
    ASSERT_FALSE(deleted.is_bad()) << to_string(deleted.status_code());

    const auto disabled = instance->try_disable_sync();
    EXPECT_TRUE(disabled.is_good()) << to_string(disabled.status_code());
  }
  ::ua::test_utils::drain_with_timeout(pool);
}

// A Condition whose Nodes are held by a namespace whose Variables accept no value source cannot keep its
// Variables' Values. Its initialisation fails with Bad_NotSupported naming the Variable, as add_method fails
// on a namespace whose Methods accept no call handler, rather than answering Good with Variables that never
// change. Two namespaces: one whose Methods accept handlers and whose Variables hide their probe, and a
// DescribedNodes namespace, whose Nodes give neither probe. The control is the first test's namespace, on
// which the same Condition initialises.
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-04-A-CONDITION-ON-A-NAMESPACE-WITHOUT-VALUE-SOURCES-FAILS-TO-INITIALISE, scope=function)
TEST(ConditionSourceProbe, AConditionOnANamespaceWithoutValueSourcesFailsToInitialise)
{
  const auto initialiseOn = [](std::shared_ptr<Namespace> nameSpace, const char* what)
  {
    boost::asio::thread_pool pool{2};
    {
      auto addressSpace =
        AddressSpace::create("uri:test:condition-without-value-sources", pool.get_executor());
      import_namespace_zero(addressSpace);
      const auto index = addressSpace.try_add_namespace_sync(nameSpace);
      ASSERT_TRUE(index.is_good()) << what << ": " << to_string(index.status_code());
      // The Condition's Nodes are created in its source's namespace.
      const NodeId sourceId{index.value(), 100u};
      auto source = addressSpace.try_create_node_sync(sourceId, NodeClass::Object, {});
      ASSERT_TRUE(source.is_good()) << what << ": " << to_string(source.status_code());
      source.value().set_browse_name(QualifiedName{index.value(), "NoValueSourcesSource"});

      auto sink = std::make_shared<EventIdAssigningSink>();
      auto instance = ConditionInstance::create(pool.get_executor(),
        std::make_unique<AlarmConditionLogic>(),
        NodeId{index.value(), 1000u},
        sourceId,
        String{"NoValueSourcesSource"},
        sink,
        addressSpace,
        NodeId{ObjectTypeId::AlarmConditionType});
      const auto initialized = instance->try_initialize_sync();
      EXPECT_EQ(initialized.status_code().as_status(), Status::BadNotSupported)
        << what << ": the Condition initialised with Variables nothing keeps: "
        << to_string(initialized.status_code());
      ASSERT_NE(initialized.shared_detail(), nullptr) << what;
      EXPECT_EQ(initialized.shared_detail()->code, "ValueSourcesNotSupported")
        << what << ": " << to_string(initialized.status_code());
    }
    ::ua::test_utils::drain_with_timeout(pool);
  };

  boost::asio::thread_pool executorPool{1};
  initialiseOn(ua::test::PostingWritesNamespace::create("urn:test:condition-without-value-sources:hidden",
                 executorPool.get_executor(),
                 ua::test::PostingWritesNamespace::CallHandlers::Accepted,
                 ua::test::PostingWritesNamespace::ValueSources::Refused),
    "a namespace whose Variables hide their value source probe");
  initialiseOn(std::make_shared<ua::test::DescribedConformanceNamespace>(
                 String{"urn:test:condition-without-value-sources:described"}),
    "a DescribedNodes namespace");
  ::ua::test_utils::drain_with_timeout(executorPool);
}
