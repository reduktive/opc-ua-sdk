// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How a MonitoredItem on DefaultUserRolePermissions is fed (DL-124 (5), NR-49): the publication installs a
// per-Session source on the Property, which cannot report its Value through notify_value_changed, so it sets
// the Property's MinimumSamplingInterval to -1 and an item at interval 0 is sampled for the Subscription's
// current caller.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "namespace_registration_coordinator_test_access.h"
#include "ua_access_control.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_type_registration.h"
#include "ua_default_namespace.h"
#include "ua_file_stream.h"
#include "ua_namespace_metadata_publication.h"
#include "ua_namespace_monitoring.h"
#include "ua_node_accessor.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"
#include "ua_role_permission_type.h"
#include "ua_security_policy.h"
#include "ua_sinks.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

void load_ns0(AddressSpace& addressSpace, StructureFactory& structureFactory)
{
  const auto configuration = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(configuration);
  auto lookup = namespace_array_utils::get_index_lookup_function(addressSpace);
  const CodecNamespaceContext namespaceContext{std::move(lookup), {}, {}, {}};
  register_ua_data_types_with_factory(namespaceContext, &structureFactory, &structureFactory);

  FileStream input{"NodeSet2.xml"};
  input.open_for_read();
  auto nodeSets = xml::nodeset::Parser::parse(limits,
    input,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    xml::nodeset::Parser::GetDependentModelCallback{});
  auto importer = xml::nodeset::ImportEngine::create(limits, addressSpace, nodeSets, {});
  importer->import_all_sync({}, {});
}

/// The one local child of @p parent reached by a forward @p referenceType Reference and named @p browseName,
/// or a null NodeId.
NodeId child(AddressSpace& addressSpace, const NodeId& parent, const NodeId& referenceType,
  const QualifiedName& browseName)
{
  auto parentNode = addressSpace.try_find_node_sync(parent);
  if (parentNode.is_bad())
    return {};
  std::vector<NodeId> matches;
  for (const auto& reference : parentNode.value().get_references_sync())
  {
    if (!reference.is_forward() || reference.is_remote() || reference.type_id() != referenceType ||
        !reference.target_id().is_local())
      continue;
    const auto targetId = reference.target_id().node_id();
    auto target = addressSpace.try_find_node_sync(targetId);
    if (target.is_good() && target.value().get_browse_name() == browseName)
      matches.push_back(targetId);
  }
  EXPECT_EQ(matches.size(), 1u);
  return matches.size() == 1 ? matches.front() : NodeId{};
}

RolePermissionType permission(NodeId roleId, PermissionType permissions)
{
  RolePermissionType result;
  result.role_id() = std::move(roleId);
  result.permissions() = permissions;
  return result;
}

/// A Session caller holding @p roles.
std::shared_ptr<const CallerInfo> caller_with(std::vector<NodeId> roles)
{
  auto endpoint = std::make_shared<EndpointSecurityContext>();
  endpoint->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  auto caller = std::make_shared<CallerInfo>();
  caller->identity = std::make_shared<const AccessIdentity>(AccessIdentityKey{92},
    std::move(roles),
    std::make_shared<UserIdentity>(),
    std::move(endpoint),
    String{"urn:test:durp-sampling"});
  return caller;
}

std::vector<RolePermissionType> role_permissions(const DataValue& dataValue)
{
  std::vector<RolePermissionType> result;
  if (!dataValue.value().is_array_of_structure())
    return result;
  const auto& values = dataValue.value().as<Array<RefStructure<Structure>>>();
  for (size_t index = 0; index < values.size(); ++index)
  {
    if (const auto* entry = dynamic_cast<const RolePermissionType*>(values[index].get()))
      result.push_back(*entry);
  }
  return result;
}

/// A sink that records the samples it receives and answers the caller the test sets, as a Subscription's
/// sink answers its Session's current caller (NR-49).
class CallerSink final : public SampleSink
{
public:
  explicit CallerSink(std::shared_ptr<const CallerInfo> caller) : mCaller(std::move(caller))
  {}

  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    {
      const std::lock_guard lock{mMutex};
      for (auto& sample : samples)
        mValues.push_back(std::move(sample.second));
    }
    mCv.notify_all();
  }

  void invalidate(IntegerId, StatusCode) override
  {}

  void detach() override
  {}

  std::shared_ptr<const CallerInfo> caller() const override
  {
    const std::lock_guard lock{mMutex};
    return mCaller;
  }

  void set_caller(std::shared_ptr<const CallerInfo> caller)
  {
    const std::lock_guard lock{mMutex};
    mCaller = std::move(caller);
  }

  /// Waits until a sample carrying exactly @p expected arrives, or @p timeout passes.
  bool wait_for(const std::vector<RolePermissionType>& expected, std::chrono::milliseconds timeout)
  {
    std::unique_lock lock{mMutex};
    return mCv.wait_for(lock,
      timeout,
      [&]
      {
        for (const auto& value : mValues)
        {
          if (role_permissions(value) == expected)
            return true;
        }
        return false;
      });
  }

  size_t samples() const
  {
    const std::lock_guard lock{mMutex};
    return mValues.size();
  }

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;
  std::shared_ptr<const CallerInfo> mCaller;
  std::vector<DataValue> mValues;
};

}  // namespace

// DL-124 (5), NR-49: once published with its per-Session source, DefaultUserRolePermissions has the
// MinimumSamplingInterval -1, and an item on it at interval 0 follows a change of the Subscription's caller:
// it receives the Observer's entry, then the Operator's once the sink's caller holds the Operator Role.
// Write-fed (the Property's imported or instantiated 0), the item keeps the first caller's array, since
// nothing is written. Control: the first caller's array arrives either way.
// @relation(AC-COMP-SVR-NAMESPACE-MONITORING-HELPER-02-DEFAULT-USER-ROLE-PERMISSIONS-IS-SAMPLED-FOR-THE-CURRENT-CALLER, scope=function)
TEST(DefaultUserRolePermissionsSampling, TheUserPropertyIsSampledForTheSubscriptionsCurrentCaller)
{
  boost::asio::thread_pool pool;
  {
    AddressSpace addressSpace = AddressSpace::create("urn:durp-sampling-host", pool.get_executor());
    StructureFactory structureFactory;
    load_ns0(addressSpace, structureFactory);
    auto publication = NamespaceMetadataPublication::create(addressSpace);
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);

    const auto observerEntry = permission(NodeId{ObjectId::WellKnownRole_Observer},
      PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read});
    const auto operatorEntry = permission(NodeId{ObjectId::WellKnownRole_Operator},
      PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Write});
    const std::vector<RolePermissionType> defaults{observerEntry, operatorEntry};
    const auto namespaceIndex =
      addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:durp-sampling", defaults));

    const auto metadata = child(addressSpace,
      NodeId{ObjectId::Server_Namespaces},
      NodeId{ReferenceTypeId::HasComponent},
      QualifiedName{namespaceIndex, "urn:durp-sampling"});
    const auto propertyId = child(addressSpace,
      metadata,
      NodeId{ReferenceTypeId::HasProperty},
      QualifiedName{0, "DefaultUserRolePermissions"});
    ASSERT_FALSE(propertyId.is_null());

    auto property = addressSpace.try_find_sync<VariableAccessor>(propertyId);
    ASSERT_TRUE(property.is_good()) << to_string(property.status_code());
    const auto minimumSamplingInterval = property.value().get_minimum_sampling_interval();
    ASSERT_TRUE(minimumSamplingInterval.has_value());
    EXPECT_DOUBLE_EQ(*minimumSamplingInterval, -1);

    auto holder = addressSpace.namespace_array().get_namespace(propertyId.namespace_index());
    ASSERT_NE(holder, nullptr);
    auto item = std::make_shared<CallerSink>(caller_with({NodeId{ObjectId::WellKnownRole_Observer}}));
    std::vector<MonitoringCreateItem> items{{.nodeId = propertyId,
      .attributeId = AttributeId::Value,
      .monitoredItemId = 1,
      .samplingInterval = 0,
      .queueSize = 10,
      .sink = item}};
    auto promise = std::make_shared<std::promise<BatchResult<MonitoringCreateItemResult>>>();
    auto future = promise->get_future();
    holder->create_monitoring_async(RequestInfo{},
      nullptr,
      items,
      [promise](BatchResult<MonitoringCreateItemResult> results) { promise->set_value(std::move(results)); });
    ASSERT_EQ(future.wait_for(2s), std::future_status::ready);
    auto created = future.get();
    ASSERT_EQ(created.items.size(), 1u);
    ASSERT_TRUE(created.items.front().is_good()) << to_string(created.items.front().status_code());
    const auto handle = created.items.front().value().handle;

    ASSERT_TRUE(item->wait_for({observerEntry}, 3s)) << item->samples() << " samples";
    item->set_caller(caller_with({NodeId{ObjectId::WellKnownRole_Operator}}));
    EXPECT_TRUE(item->wait_for({operatorEntry}, 3s)) << item->samples() << " samples";

    const MonitoringHandle handles[]{handle};
    auto deleted = std::make_shared<std::promise<void>>();
    auto deletedFuture = deleted->get_future();
    holder->delete_monitoring_async(
      RequestInfo{}, handles, [deleted](BatchResult<VoidResult>) { deleted->set_value(); });
    EXPECT_EQ(deletedFuture.wait_for(2s), std::future_status::ready);
  }
  ::ua::test_utils::drain_with_timeout(pool);
}
