// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for the admin-only Read gate on the raw `RolePermissions`
/// Attribute / `DefaultRolePermissions` Property.
///
/// Closes the P3 slice of SVR-SECADMIN-047 (per-Node RolePermissions Attribute
/// admin-only Read). The NamespaceMetadata `DefaultRolePermissions` Property
/// variants (and the vendor-specific omission) land in Phase P4 when the
/// Property is populated; the predicate gate is the shared enforcement point.
///
/// The service-level wiring (`AttributeServiceSet` rejecting a non-admin Read of
/// the RolePermissions Attribute with `Bad_UserAccessDenied`) is exercised by
/// the integration mirror `server_security_role_permissions_admin_read_integration`.

#include <cstdio>

#include <gtest/gtest.h>

#include "batch_recording_namespace.h"
#include "per_item_join.h"
#include "posting_writes_namespace.h"
#include "test_utilities.h"

#include "namespace_registration_coordinator_test_access.h"
#include "ua_address_space.h"
#include "ua_access_control.h"
#include "ua_access_level_ex_type.h"
#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_type_registration.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_file_stream.h"
#include "ua_memory_stream.h"
#include "ua_namespace_metadata_publication.h"
#include "ua_namespace_metadata.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_import.h"
#include "ua_nodeset_parser.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_role_permission_type.h"
#include "ua_security_policy.h"
#include "ua_structure_factory.h"
#include "ua_variable_id.h"

#include <boost/asio/thread_pool.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

NodeId security_admin_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)};
}

AccessControl::Verdict authorize_one(AccessControl& accessControl, const AccessIdentity& identity,
  const NodeAccessor& node, AccessOperation operation)
{
  auto identityView = std::shared_ptr<const AccessIdentity>(&identity, [](const AccessIdentity*) {});
  std::promise<std::vector<AccessControl::Verdict>> promise;
  auto future = promise.get_future();
  const std::array items{AccessControl::Item{node, operation}};
  accessControl.authorize_async(ua::RequestInfo{},
    std::move(identityView),
    items,
    identity.endpoint(),
    [&promise](std::vector<AccessControl::Verdict> verdicts) { promise.set_value(std::move(verdicts)); });
  auto verdicts = future.get();
  if (verdicts.size() != 1)
    throw std::logic_error{"single-item authorization returned the wrong cardinality"};
  return std::move(verdicts.front());
}

class DefaultRolePermissionsPropertyTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mPool.get_executor();
    mAddressSpace = std::make_unique<AddressSpace>(AddressSpace::create("urn:drp-tests", mExecutor));
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mPool);
  }

  std::shared_ptr<const AccessIdentity> make_identity(std::vector<NodeId> roles) const
  {
    auto user = std::make_shared<UserIdentity>();
    auto endpoint = std::make_shared<EndpointSecurityContext>();
    endpoint->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    return std::make_shared<AccessIdentity>(AccessIdentityKey{1},
      std::move(roles),
      std::move(user),
      std::move(endpoint),
      String{"urn:test:default-role-permissions"});
  }

  NodeAccessor make_admin_only_node()
  {
    auto node = mAddressSpace->try_create_node_sync(NodeId{1, 9000u}, NodeClass::Variable, {}).value();
    RolePermissionType permission;
    permission.role_id() = security_admin_role_id();
    permission.permissions() = PermissionType{PermissionType::Bit::ReadRolePermissions};
    node.set_role_permissions(std::vector<RolePermissionType>{permission});
    return node;
  }

  AccessControl::Verdict authorize(const AccessIdentity& identity, const NodeAccessor& node)
  {
    AccessControl accessControl{*mAddressSpace, std::chrono::milliseconds{100}};
    return authorize_one(accessControl, identity, node, AccessOperation::ReadRolePermissions);
  }

  boost::asio::thread_pool mPool;
  boost::asio::any_io_executor mExecutor;
  std::unique_ptr<AddressSpace> mAddressSpace;
};

// @relation(SVR-SECADMIN-047, scope=function)
TEST_F(DefaultRolePermissionsPropertyTest, AdminReadAllowed)
{
  auto node = make_admin_only_node();
  auto identity = make_identity({security_admin_role_id()});
  EXPECT_TRUE(authorize(*identity, node).permitted);
}

// @relation(SVR-SECADMIN-047, scope=function)
TEST_F(DefaultRolePermissionsPropertyTest, NonAdminReadDenied)
{
  auto node = make_admin_only_node();
  auto identity = make_identity({});
  EXPECT_FALSE(authorize(*identity, node).permitted);
}

// @relation(SVR-SECADMIN-047, scope=function)
TEST_F(DefaultRolePermissionsPropertyTest, NonSecurityAdminBitInMaskStillDenied)
{
  auto node = make_admin_only_node();
  auto identity = make_identity({NodeId{ObjectId::WellKnownRole_Observer}});
  EXPECT_FALSE(authorize(*identity, node).permitted);
}

TEST_F(DefaultRolePermissionsPropertyTest, AbsentSecurityAdminGrantFailsClosed)
{
  auto node = make_admin_only_node();
  auto identity = make_identity({NodeId{ObjectId::WellKnownRole_ConfigureAdmin}});
  EXPECT_FALSE(authorize(*identity, node).permitted);
}

namespace
{

void load_ns0(AddressSpace& addressSpace, StructureFactory& structureFactory);
RolePermissionType permission(NodeId roleId, PermissionType permissions);

class NamespaceMetadataPublicationTest : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    sApplicationPool = std::make_unique<boost::asio::thread_pool>();
    sApplicationAddressSpace.emplace(
      AddressSpace::create("urn:nmp-standard", sApplicationPool->get_executor()));
    load_ns0(*sApplicationAddressSpace, sStructureFactory);
    sApplicationAddressSpace->add_namespace_sync(
      sApplicationAddressSpace->create_namespace("urn:nmp-vendor", {}));
    sApplicationAddressSpace->add_namespace_sync(
      sApplicationAddressSpace->create_namespace("urn:nmp-unspecified", {}));
    sApplicationAddressSpace->add_namespace_sync(
      sApplicationAddressSpace->create_namespace("urn:nmp-idempotent", {}));
    sApplicationAddressSpace->add_namespace_sync(
      sApplicationAddressSpace->create_namespace("urn:nmp-constant", {}));
    sApplicationAddressSpace->add_namespace_sync(
      sApplicationAddressSpace->create_namespace("urn:nmp-version-first", {}));
    sApplicationAddressSpace->add_namespace_sync(
      sApplicationAddressSpace->create_namespace("urn:nmp-version-second", {}));
    const std::vector<RolePermissionType> governedDefaults{
      permission(NodeId{ObjectId::WellKnownRole_Observer}, PermissionType{PermissionType::Bit::Browse}),
      permission(NodeId{ObjectId::WellKnownRole_Operator}, PermissionType{PermissionType::Bit::Read})};
    sApplicationAddressSpace->add_namespace_sync(
      sApplicationAddressSpace->create_namespace("urn:nmp-governing-map",
        governedDefaults,
        AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired}));
  }

  static void TearDownTestSuite()
  {
    sApplicationAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(*sApplicationPool);
    sApplicationPool.reset();
  }

  static AddressSpace& application_address_space()
  {
    return *sApplicationAddressSpace;
  }

  static uint16_t application_namespace_index(string_view uri)
  {
    return application_address_space().namespace_array().get_namespace_index(uri);
  }

  inline static std::unique_ptr<boost::asio::thread_pool> sApplicationPool;
  inline static std::optional<AddressSpace> sApplicationAddressSpace;
  inline static StructureFactory sStructureFactory;
};

}  // namespace

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

std::vector<NodeId> matching_children(AddressSpace& addressSpace, const NodeId& parent,
  const NodeId& referenceType, const QualifiedName& browseName)
{
  std::vector<NodeId> matches;
  auto parentResult = addressSpace.try_find_node_sync(parent);
  if (parentResult.is_bad())
  {
    return matches;
  }

  for (const auto& reference : parentResult.value().get_references_sync())
  {
    if (!reference.is_forward() || reference.is_remote() || reference.type_id() != referenceType ||
        !reference.target_id().is_local())
    {
      continue;
    }
    const auto targetId = reference.target_id().node_id();
    auto target = addressSpace.try_find_node_sync(targetId);
    if (target.is_good() && target.value().get_browse_name() == browseName)
    {
      matches.push_back(targetId);
    }
  }
  return matches;
}

DataValueResult read_property(AddressSpace& addressSpace, const NodeId& metadata, string_view propertyName)
{
  const auto matches = matching_children(
    addressSpace, metadata, NodeId{ReferenceTypeId::HasProperty}, QualifiedName{0, propertyName});
  if (matches.size() != 1)
  {
    return StatusCode{Status::BadNodeIdUnknown};
  }
  auto property = addressSpace.try_find_sync<VariableAccessor>(matches.front());
  if (property.is_bad())
  {
    return DataValueResult{property.status_code()};
  }
  return property.value().try_read_value_sync();
}

/// Reads a Property's Value the way a Session does - with an identity in scope.
///
/// `try_read_value_sync` passes no identity, which is the right answer for an internal caller but not
/// the one a client gets: a Property whose value is produced per Session declines the synchronous path
/// entirely, so the identity has to travel through the asynchronous read.
DataValueResult read_property_as(AddressSpace& addressSpace, const NodeId& metadata, string_view propertyName,
  const AccessIdentity& identity)
{
  const auto matches = matching_children(
    addressSpace, metadata, NodeId{ReferenceTypeId::HasProperty}, QualifiedName{0, propertyName});
  if (matches.size() != 1)
  {
    return StatusCode{Status::BadNodeIdUnknown};
  }
  auto property = addressSpace.try_find_sync<VariableAccessor>(matches.front());
  if (property.is_bad())
  {
    return DataValueResult{property.status_code()};
  }
  ReadValueId nodeToRead;
  nodeToRead.node_id() = matches.front();
  nodeToRead.attribute_id() = utils::to_underlying(AttributeId::Value);
  // The read's caller holds only the identity; the test holds the identity for the whole call.
  CallerInfo caller;
  caller.identity = std::shared_ptr<const AccessIdentity>(&identity, [](const AccessIdentity*) {});
  std::promise<DataValueResult> promise;
  auto future = promise.get_future();
  property.value().read_value_async({},
    true,
    nodeToRead,
    &caller,
    [&promise](DataValueResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

std::vector<RolePermissionType> role_permissions(const DataValue& dataValue)
{
  std::vector<RolePermissionType> result;
  if (!dataValue.value().is_array_of_structure())
  {
    return result;
  }
  const auto& values = dataValue.value().as<Array<RefStructure<Structure>>>();
  for (size_t index = 0; index < values.size(); ++index)
  {
    if (const auto* permission = dynamic_cast<const RolePermissionType*>(values[index].get()))
    {
      result.push_back(*permission);
    }
  }
  return result;
}

RolePermissionType permission(NodeId roleId, PermissionType permissions)
{
  RolePermissionType result;
  result.role_id() = std::move(roleId);
  result.permissions() = permissions;
  return result;
}

VoidResult prepare(AddressSpace addressSpace, std::vector<NamespaceMetadataSnapshot> namespaces,
  std::atomic<size_t>* callbackCount = nullptr)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  publication->prepare_async(std::move(namespaces),
    [&promise, callbackCount](VoidResult result)
    {
      if (callbackCount == nullptr || callbackCount->fetch_add(1) == 0)
      {
        promise.set_value(std::move(result));
      }
    });
  return future.get();
}

std::pair<std::shared_ptr<NamespaceMetadataPublication>, VoidResult> prepare_publication(
  AddressSpace addressSpace, std::vector<NamespaceMetadataSnapshot> namespaces)
{
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  publication->prepare_async(
    std::move(namespaces), [&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return {publication, future.get()};
}

AccessIdentity publication_identity(std::vector<NodeId> roles)
{
  auto endpoint = std::make_shared<EndpointSecurityContext>();
  endpoint->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  return AccessIdentity{AccessIdentityKey{91},
    std::move(roles),
    std::make_shared<UserIdentity>(),
    std::move(endpoint),
    String{"urn:test:metadata-publication"}};
}

NodeId property_node_id(AddressSpace& addressSpace, const NodeId& metadata, string_view browseName)
{
  const auto matches = matching_children(
    addressSpace, metadata, NodeId{ReferenceTypeId::HasProperty}, QualifiedName{0, browseName});
  EXPECT_EQ(matches.size(), 1u);
  if (matches.empty())
  {
    return {};
  }
  return matches.front();
}

Result<std::vector<NodeId>> enumerate_nodes(AddressSpace addressSpace, uint16_t namespaceIndex)
{
  std::promise<Result<std::vector<NodeId>>> promise;
  auto future = promise.get_future();
  addressSpace.enumerate_nodes_async(
    namespaceIndex, [&promise](Result<std::vector<NodeId>> result) { promise.set_value(std::move(result)); });
  return future.get();
}

Result<std::vector<NodeId>> enumerate_namespace_nodes(Namespace& nameSpace)
{
  std::promise<Result<std::vector<NodeId>>> promise;
  auto future = promise.get_future();
  nameSpace.enumerate_nodes_async(RequestInfo{},
    [&promise](Result<std::vector<NodeId>> result) mutable { promise.set_value(std::move(result)); });
  return future.get();
}

constexpr string_view importedMetadataNodeSet = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris><Uri>urn:test:imported-metadata</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;i=7000" BrowseName="1:urn:test:imported-metadata">
    <References>
      <Reference ReferenceType="i=40">i=11616</Reference>
      <Reference ReferenceType="i=46">ns=1;i=7001</Reference>
      <Reference ReferenceType="i=46">ns=1;i=7002</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=7001" BrowseName="0:NamespaceUri" ParentNodeId="ns=1;i=7000"
              DataType="i=12">
    <References>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=7000</Reference>
      <Reference ReferenceType="i=40">i=68</Reference>
    </References>
    <Value><uax:String>urn:test:imported-metadata</uax:String></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=7002" BrowseName="0:NamespaceVersion" ParentNodeId="ns=1;i=7000"
              DataType="i=12">
    <References>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=7000</Reference>
      <Reference ReferenceType="i=40">i=68</Reference>
    </References>
    <Value><uax:String>document-version-one</uax:String></Value>
  </UAVariable>
</UANodeSet>)";

constexpr string_view bootstrapMetadataNodeSet = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris><Uri>urn:nmp-bootstrap-import</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;i=7200" BrowseName="1:urn:nmp-bootstrap-import">
    <References>
      <Reference ReferenceType="i=40">i=11616</Reference>
      <Reference ReferenceType="i=46">ns=1;i=7201</Reference>
      <Reference ReferenceType="i=46">ns=1;i=7202</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=7201" BrowseName="0:NamespaceUri" ParentNodeId="ns=1;i=7200"
              DataType="i=12">
    <References>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=7200</Reference>
      <Reference ReferenceType="i=40">i=68</Reference>
    </References>
    <Value><uax:String>urn:nmp-bootstrap-import</uax:String></Value>
  </UAVariable>
  <UAVariable NodeId="ns=1;i=7202" BrowseName="0:NamespaceVersion" ParentNodeId="ns=1;i=7200"
              DataType="i=12">
    <References>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=7200</Reference>
      <Reference ReferenceType="i=40">i=68</Reference>
    </References>
    <Value><uax:String>bootstrap-document-version</uax:String></Value>
  </UAVariable>
</UANodeSet>)";

constexpr string_view conflictingImportedMetadataNodeSet =
  R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris><Uri>urn:test:imported-metadata</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;i=7100" BrowseName="1:urn:test:imported-metadata">
    <References>
      <Reference ReferenceType="i=40">i=11616</Reference>
      <Reference ReferenceType="i=46">ns=1;i=7101</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=7101" BrowseName="0:NamespaceUri" ParentNodeId="ns=1;i=7100"
              DataType="i=12">
    <References>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=7100</Reference>
      <Reference ReferenceType="i=40">i=68</Reference>
    </References>
    <Value><uax:String>urn:test:imported-metadata</uax:String></Value>
  </UAVariable>
</UANodeSet>)";

constexpr string_view invalidImportedMetadataNodeSet = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd"
           xmlns:uax="http://opcfoundation.org/UA/2008/02/Types.xsd">
  <NamespaceUris><Uri>urn:test:invalid-imported-metadata</Uri></NamespaceUris>
  <UAObject NodeId="ns=1;i=7300" BrowseName="1:urn:test:invalid-imported-metadata">
    <References>
      <Reference ReferenceType="i=40">i=11616</Reference>
      <Reference ReferenceType="i=46">ns=1;i=7301</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=7301" BrowseName="0:NamespaceUri" ParentNodeId="ns=1;i=7300"
              DataType="i=12">
    <References>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=7300</Reference>
      <Reference ReferenceType="i=40">i=68</Reference>
    </References>
    <Value><uax:String>urn:test:not-the-registered-uri</uax:String></Value>
  </UAVariable>
</UANodeSet>)";

Result<NodeSetImportSummary> import_metadata_nodeset(AddressSpace addressSpace,
  boost::asio::any_io_executor executor, string_view xml, shared_ptr<Namespace>* allocatedNamespace = nullptr)
{
  memory_stream_device::ExternalReadOnly device{
    std::span<const std::byte>{reinterpret_cast<const std::byte*>(xml.data()), xml.size()}};
  MemoryStream<memory_stream_device::ExternalReadOnly> stream{device};
  auto parsed = try_parse_nodeset_sync(stream, NodeSetParseOptions{});
  if (parsed.is_bad())
  {
    return Result<NodeSetImportSummary>{parsed.status_code(), parsed.shared_detail()};
  }

  NodeSetImportOptions options;
  options.namespaceFactory = [executor = std::move(executor), allocatedNamespace](
                               string_view uri) -> shared_ptr<Namespace>
  {
    auto nameSpace = default_ns::Namespace::create(uri, executor);
    if (allocatedNamespace != nullptr)
    {
      *allocatedNamespace = nameSpace;
    }
    return nameSpace;
  };
  return try_import_nodeset_sync(std::move(addressSpace), std::move(parsed).value(), std::move(options));
}

VoidResult prepare_installed_namespaces(AddressSpace& addressSpace)
{
  std::promise<VoidResult> promise;
  auto future = promise.get_future();
  NamespaceRegistrationCoordinatorTestAccess::prepare_installed_namespaces_async(
    addressSpace, [&promise](VoidResult result) { promise.set_value(std::move(result)); });
  return future.get();
}

class OpaqueNonCachingNamespace final : public Namespace
{
public:
  static std::shared_ptr<OpaqueNonCachingNamespace> create(String uri, boost::asio::any_io_executor executor)
  {
    return std::make_shared<OpaqueNonCachingNamespace>(std::move(uri), std::move(executor));
  }

  // Backed by real storage so the namespace genuinely OWNS nodes. Its metadata Object is created in
  // namespace 1 like every other, so authorizing that Object would route to namespace 1 and never
  // reach this namespace's effective_permissions - which is what the caching assertions measure.
  OpaqueNonCachingNamespace(String uri, boost::asio::any_io_executor executor)
    : mUri(uri), mStore(default_ns::Namespace::create(static_cast<string_view>(uri), std::move(executor)))
  {
    std::static_pointer_cast<default_ns::Namespace>(mStore)->set_namespace_defaults(
      std::nullopt, AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});
  }

  String uri() const override
  {
    return mUri;
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    mStore->shutdown_async(std::move(callback));
  }

  // Every Node member is the store's: the Nodes it answers are the store's own.
  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mStore->find_nodes_async(request, nodeIds, maxAge, std::move(complete));
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    return mStore->find_node(nodeId, maxAge);
  }

  void enumerate_nodes_async(
    const RequestInfo& request, std::function<void(Result<std::vector<NodeId>>)> complete) override
  {
    mStore->enumerate_nodes_async(request, std::move(complete));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    mStore->read_references_async(request, queries, std::move(complete));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    mStore->read_values_async(request, caller, items, maxAge, setSourceTimestamp, std::move(complete));
  }

  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mStore->write_async(request, caller, items, std::move(complete));
  }

  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    mStore->create_nodes_async(request, nodes, std::move(complete));
  }

  void delete_nodes_async(const RequestInfo& request, std::span<const NodeId> nodes, ReferenceHalves halves,
    std::function<void(BatchResult<DeleteNodeResult>, std::vector<VersionedNode>)> complete) override
  {
    mStore->delete_nodes_async(request, nodes, halves, std::move(complete));
  }

  void add_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mStore->add_references_async(request, changes, std::move(complete));
  }

  void remove_references_async(const RequestInfo& request, std::span<const ReferenceChange> changes,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override
  {
    mStore->remove_references_async(request, changes, std::move(complete));
  }

  std::optional<PermissionType> effective_permissions(const AccessIdentity&, const Node*) const override
  {
    mImmediateCalls.fetch_add(1, std::memory_order_relaxed);
    return std::nullopt;
  }

  void effective_permissions_async(const RequestInfo&, shared_ptr<const AccessIdentity>,
    std::optional<std::vector<NodeId>> nodes, EffectivePermissionsCallback callback) override
  {
    mAsyncCalls.fetch_add(1, std::memory_order_relaxed);
    EffectivePermissionsResult result;
    const auto count = nodes ? nodes->size() : 1U;
    result.items.reserve(count);
    for (std::size_t index = 0; index < count; ++index)
      result.items.emplace_back(PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read});
    callback(std::move(result));
  }

  std::optional<std::vector<RolePermissionType>> default_role_permissions() const override
  {
    return std::nullopt;
  }

  std::optional<AccessRestrictionType> default_access_restrictions() const override
  {
    return AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired};
  }

  std::size_t immediate_calls() const noexcept
  {
    return mImmediateCalls.load(std::memory_order_relaxed);
  }

  std::size_t async_calls() const noexcept
  {
    return mAsyncCalls.load(std::memory_order_relaxed);
  }

private:
  String mUri;
  shared_ptr<Namespace> mStore;
  mutable std::atomic<std::size_t> mImmediateCalls{0};
  mutable std::atomic<std::size_t> mAsyncCalls{0};

  VoidResult on_attached(const NamespaceContext& context) override
  {
    return mStore->attach(context);
  }
};

class FailingMetadataNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<FailingMetadataNamespace> create(
    string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<FailingMetadataNamespace>{new FailingMetadataNamespace{uri, std::move(executor)}};
  }

  // Refuses the second Node it is asked to create while the failure is armed; creates every other.
  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override
  {
    auto join = std::make_shared<ua::test::PerItemJoin<NodeResult>>(nodes.size(), std::move(complete));
    for (std::size_t index = 0; index < nodes.size(); ++index)
    {
      const auto call = mCreateCalls.fetch_add(1, std::memory_order_relaxed) + 1U;
      if (mFailureEnabled.load(std::memory_order_acquire) && call == 2U)
      {
        join->answer(index, NodeResult{mInjectedFailure});
        continue;
      }
      default_ns::Namespace::create_nodes_async(request,
        nodes.subspan(index, 1),
        [join, index](BatchResult<NodeResult> created)
        { join->answer(index, ua::test::only_item(std::move(created))); });
    }
    join->started();
  }

  void allow_creation() noexcept
  {
    mFailureEnabled.store(false, std::memory_order_release);
  }

  shared_ptr<const ErrorDetail> injected_detail() const noexcept
  {
    return mInjectedFailure.shared_detail();
  }

  size_t create_calls() const noexcept
  {
    return mCreateCalls.load(std::memory_order_relaxed);
  }

private:
  FailingMetadataNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor)),
      mInjectedFailure(Status::BadResourceUnavailable,
        ErrorDetail::build("InjectedMetadataCreateFailure",
          "The test namespace refused a metadata child after creating its root", "FailingMetadataNamespace"))
  {}

  std::atomic_size_t mCreateCalls{0};
  std::atomic_bool mFailureEnabled{true};
  StatusCode mInjectedFailure;
};

NodeId unique_metadata_node(AddressSpace& addressSpace, uint16_t namespaceIndex, string_view uri)
{
  const auto matches = matching_children(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{namespaceIndex, uri});
  EXPECT_EQ(matches.size(), 1u);
  if (matches.empty())
  {
    return {};
  }
  return matches.front();
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-METADATA-PUBLICATION-01-LIVE-KINDS, scope=function)
TEST_F(NamespaceMetadataPublicationTest,
  LiveRegistrationPublishesEveryNamespaceKindAndUpdatesExistingAccessControl)
{
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-live", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);
  AccessControl accessControl{addressSpace, std::chrono::milliseconds{100}};

  const std::vector<RolePermissionType> standardDefaults{permission(NodeId{ObjectId::WellKnownRole_Observer},
    PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  auto standard = addressSpace.create_namespace("urn:nmp-live-standard", standardDefaults);
  const auto standardIndex = addressSpace.add_namespace_sync(std::move(standard));

  auto opaque = OpaqueNonCachingNamespace::create(String{"urn:nmp-live-opaque"}, pool.get_executor());
  const auto opaqueIndex = addressSpace.add_namespace_sync(opaque);
  EXPECT_EQ(standardIndex, 2);
  EXPECT_EQ(opaqueIndex, 3);

  const auto standardMetadata = unique_metadata_node(addressSpace, standardIndex, "urn:nmp-live-standard");
  const auto opaqueMetadata = unique_metadata_node(addressSpace, opaqueIndex, "urn:nmp-live-opaque");
  // The SDK creates metadata Objects in namespace 1, whatever they describe. Governance follows the
  // NodeId, so both are governed by namespace 1 and neither needs a recorded exception.
  EXPECT_EQ(standardMetadata.namespace_index(), 1);
  EXPECT_EQ(opaqueMetadata.namespace_index(), 1);
  EXPECT_EQ(matching_children(addressSpace,
              standardMetadata,
              NodeId{ReferenceTypeId::HasProperty},
              QualifiedName{0, "DefaultRolePermissions"})
              .size(),
    1U);
  EXPECT_EQ(matching_children(addressSpace,
              standardMetadata,
              NodeId{ReferenceTypeId::HasProperty},
              QualifiedName{0, "DefaultUserRolePermissions"})
              .size(),
    1U);
  EXPECT_TRUE(matching_children(addressSpace,
    opaqueMetadata,
    NodeId{ReferenceTypeId::HasProperty},
    QualifiedName{0, "DefaultRolePermissions"})
                .empty());
  EXPECT_TRUE(matching_children(addressSpace,
    opaqueMetadata,
    NodeId{ReferenceTypeId::HasProperty},
    QualifiedName{0, "DefaultUserRolePermissions"})
                .empty());
  EXPECT_EQ(opaqueMetadata.namespace_index(), 1)
    << "an SDK-created metadata Object lives in namespace 1, which is reserved for the local Server";

  const auto observer = publication_identity({NodeId{ObjectId::WellKnownRole_Observer}});
  auto standardNode = addressSpace.find_node_sync(standardMetadata);
  EXPECT_TRUE(authorize_one(accessControl, observer, standardNode, AccessOperation::Read).permitted);

  // A node this namespace genuinely owns. Its metadata Object is a namespace 1 node, so authorizing
  // that would route to namespace 1 and never consult this namespace at all.
  const NodeId opaqueOwnNode{opaqueIndex, 9200u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(opaqueOwnNode, NodeClass::Variable, {}).is_good());
  auto opaqueNode = addressSpace.find_node_sync(opaqueOwnNode);
  EXPECT_TRUE(authorize_one(accessControl, observer, opaqueNode, AccessOperation::Read).permitted);
  EXPECT_TRUE(authorize_one(accessControl, observer, opaqueNode, AccessOperation::Read).permitted);
  EXPECT_EQ(opaque->immediate_calls(), 2U);
  EXPECT_EQ(opaque->async_calls(), 2U);

  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-SVR-NAMESPACE-METADATA-PUBLICATION-02-ROLLBACK, scope=function)
//
// This test used to prove the opposite of what it proves now, and the change is the point. It injected
// a refusal into the candidate namespace's create_node, because the metadata Object was created in the
// candidate's own namespace, and asserted that the refusal rolled the whole registration back. Creating
// the Object in namespace 1 removes that failure mode rather than relocating it: namespace 1 is the
// SDK's own namespace, so creation cannot be declined, and a candidate is never asked to accept nodes it
// did not ask for. The refusal is therefore no longer reachable from this path, and registration
// succeeds while the candidate refuses everything.
//
// The rollback machinery itself is still guarded, on the two paths where creating or attaching the
// Object can still fail: RejectedNodeSetDeclarationRollsBackStagedNodesAndNamespace and
// MissingNamespacesParentPreservesRichFailureAndCompletesOnce.
//
// NOTE FOR THE CRITERION: AC-COMP-SVR-NAMESPACE-METADATA-PUBLICATION-02-ROLLBACK specifies its stimulus
// as a creation failure in the candidate namespace and its outcome as that candidate's staged resources
// being released. Neither describes the system any more. The criterion needs re-authoring - either
// retired, because its stimulus was designed out, or re-pointed at the two paths named above - and that
// is a requirements decision, not one this test should make silently.
TEST_F(NamespaceMetadataPublicationTest, CandidateRefusingNodeCreationStillGetsMetadataInNamespaceOne)
{
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-live-failure", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);
  const auto before = addressSpace.namespace_array().get_namespace_array();
  auto candidate = FailingMetadataNamespace::create("urn:nmp-live-failing-candidate", pool.get_executor());

  // The candidate refuses every node creation after its first. Registration still succeeds.
  const auto registered = addressSpace.try_add_namespace_sync(candidate);
  ASSERT_TRUE(registered.is_good()) << registered.status_code().as_uint32();
  EXPECT_EQ(registered.value(), 2);
  EXPECT_NE(addressSpace.namespace_array().get_namespace_array(), before);
  EXPECT_EQ(addressSpace.namespace_array().get_namespace_index("urn:nmp-live-failing-candidate"), 2);

  // Nothing was asked of the candidate, so its refusal never came into play and it staged nothing.
  EXPECT_EQ(candidate->create_calls(), 0u);
  auto stagedNodes = enumerate_namespace_nodes(*candidate);
  ASSERT_TRUE(stagedNodes);
  EXPECT_TRUE(stagedNodes.value().empty())
    << (stagedNodes.value().empty() ? std::string{} : to_string(stagedNodes.value().front()));

  // The Object exists, in namespace 1, linked once under Server.Namespaces.
  const auto metadata = unique_metadata_node(addressSpace, 2, "urn:nmp-live-failing-candidate");
  EXPECT_EQ(metadata.namespace_index(), 1);
  EXPECT_EQ(matching_children(addressSpace,
              NodeId{ObjectId::Server_Namespaces},
              NodeId{ReferenceTypeId::HasComponent},
              QualifiedName{2, "urn:nmp-live-failing-candidate"})
              .size(),
    1U);

  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-SVR-NAMESPACE-METADATA-PUBLICATION-03-NODESET-ADOPTION, scope=function)
TEST_F(NamespaceMetadataPublicationTest, NodeSetRegistrationAdoptsDeclaredMetadataWithoutPlaceholder)
{
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-nodeset-adoption", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);
  const auto before = addressSpace.namespace_array().get_namespace_array();

  auto imported = import_metadata_nodeset(addressSpace, pool.get_executor(), importedMetadataNodeSet);
  ASSERT_TRUE(imported) << imported.status_code().value();
  const auto namespaceIndex =
    addressSpace.namespace_array().get_namespace_index("urn:test:imported-metadata");
  ASSERT_EQ(namespaceIndex, before.size());
  const auto metadataChildren = matching_children(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{namespaceIndex, "urn:test:imported-metadata"});
  ASSERT_EQ(metadataChildren.size(), 1U);
  EXPECT_EQ(metadataChildren.front(), NodeId(namespaceIndex, 7000U));
  // Adopted from the document, so it keeps the document's namespace - and is governed by it.
  EXPECT_EQ(metadataChildren.front().namespace_index(), namespaceIndex);

  auto version = read_property(addressSpace, metadataChildren.front(), "NamespaceVersion");
  ASSERT_TRUE(version) << version.status_code().value();
  ASSERT_TRUE(version.value().value().is_string());
  EXPECT_EQ(version.value().value().as<String>(), String{"document-version-one"});

  ::ua::test_utils::drain_with_timeout(pool);
}

// CALLS-21 rule 1: a NodeSet that declares its namespace's metadata stages it through the new namespace
// before the namespace is registered, and the staging keeps no address space while that namespace holds its
// lookup.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-HELD-METADATA-STAGING-KEEPS-NO-ADDRESS-SPACE, scope=function)
TEST_F(NamespaceMetadataPublicationTest, AHeldMetadataStagingLookupKeepsNoAddressSpace)
{
  boost::asio::thread_pool pool;
  std::optional<AddressSpace> addressSpace{AddressSpace::create("urn:nmp-staging-held", pool.get_executor())};
  StructureFactory structureFactory;
  load_ns0(*addressSpace, structureFactory);
  auto publication = NamespaceMetadataPublication::create(*addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(*addressSpace, publication);
  const auto candidateIndex =
    static_cast<uint16_t>(addressSpace->namespace_array().get_namespace_array().size());

  memory_stream_device::ExternalReadOnly device{std::span<const std::byte>{
    reinterpret_cast<const std::byte*>(importedMetadataNodeSet.data()), importedMetadataNodeSet.size()}};
  MemoryStream<memory_stream_device::ExternalReadOnly> stream{device};
  auto parsed = try_parse_nodeset_sync(stream, NodeSetParseOptions{});
  ASSERT_TRUE(parsed.is_good()) << parsed.status_code().value();
  auto allocated = std::make_shared<std::promise<shared_ptr<ua::test::BatchRecordingNamespace>>>();
  auto allocatedFuture = allocated->get_future();
  NodeSetImportOptions options;
  options.namespaceFactory = [executor = pool.get_executor(), allocated, candidateIndex](
                               string_view uri) -> shared_ptr<Namespace>
  {
    auto candidate = std::make_shared<ua::test::BatchRecordingNamespace>(uri, executor);
    candidate->hold_lookups_of({NodeId{candidateIndex, 7000U}});
    allocated->set_value(candidate);
    return candidate;
  };
  auto answered = std::make_shared<std::promise<Result<NodeSetImportSummary>>>();
  auto answer = answered->get_future();
  import_nodeset_async(*addressSpace,
    std::move(parsed).value(),
    std::move(options),
    [answered](Result<NodeSetImportSummary> result) { answered->set_value(std::move(result)); });
  ASSERT_EQ(allocatedFuture.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  auto candidate = allocatedFuture.get();
  ASSERT_TRUE(candidate->wait_for_held_lookups(1, std::chrono::seconds{10})) << "the staging did not look up";

  const WeakAddressSpace handle = addressSpace->weak();
  publication.reset();
  addressSpace.reset();
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
  while (handle.lock() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  EXPECT_FALSE(handle.lock().has_value()) << "the held staging lookup keeps the address space";
  candidate->release_held_lookups();
  ASSERT_EQ(answer.wait_for(std::chrono::seconds{10}), std::future_status::ready);
  EXPECT_TRUE(answer.get().is_bad());
  candidate.reset();
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-SVR-NAMESPACE-METADATA-PUBLICATION-03-BOOTSTRAP-ADOPTION, scope=function)
TEST_F(NamespaceMetadataPublicationTest, BootstrapNamespaceAdoptsDeclarationBeforeParticipantCatchUp)
{
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-bootstrap-import", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);

  auto imported = import_metadata_nodeset(addressSpace, pool.get_executor(), bootstrapMetadataNodeSet);
  ASSERT_TRUE(imported) << imported.status_code().value();
  ASSERT_EQ(addressSpace.namespace_array().get_namespace_index("urn:nmp-bootstrap-import"), 1);

  auto publication = NamespaceMetadataPublication::create(addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);
  auto prepared = prepare_installed_namespaces(addressSpace);
  ASSERT_TRUE(prepared) << prepared.status_code().value();

  const auto metadataChildren = matching_children(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{1, "urn:nmp-bootstrap-import"});
  ASSERT_EQ(metadataChildren.size(), 1U);
  EXPECT_EQ(metadataChildren.front(), NodeId(1, 7200U));
  EXPECT_EQ(metadataChildren.front().namespace_index(), 1);

  auto version = read_property(addressSpace, metadataChildren.front(), "NamespaceVersion");
  ASSERT_TRUE(version) << version.status_code().value();
  ASSERT_TRUE(version.value().value().is_string());
  EXPECT_EQ(version.value().value().as<String>(), String{"bootstrap-document-version"});

  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-SVR-NAMESPACE-METADATA-PUBLICATION-03-STAGE-ROLLBACK, scope=function)
TEST_F(NamespaceMetadataPublicationTest, RejectedNodeSetDeclarationRollsBackStagedNodesAndNamespace)
{
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-nodeset-rollback", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);
  const auto namespaceArrayBefore = addressSpace.namespace_array().get_namespace_array();
  shared_ptr<Namespace> allocatedNamespace;

  auto rejected = import_metadata_nodeset(
    addressSpace, pool.get_executor(), invalidImportedMetadataNodeSet, &allocatedNamespace);
  ASSERT_TRUE(rejected.is_bad());
  EXPECT_EQ(rejected.status_code(), Status::BadConfigurationError);
  ASSERT_NE(rejected.shared_detail(), nullptr);
  EXPECT_EQ(rejected.shared_detail()->code, "NamespaceMetadataUriMismatch");
  EXPECT_EQ(addressSpace.namespace_array().get_namespace_array(), namespaceArrayBefore);
  EXPECT_THROW((void)addressSpace.namespace_array().get_namespace_index("urn:test:invalid-imported-metadata"),
    UaException);
  ASSERT_NE(allocatedNamespace, nullptr);
  auto remaining = enumerate_namespace_nodes(*allocatedNamespace);
  ASSERT_TRUE(remaining);
  EXPECT_TRUE(remaining.value().empty())
    << (remaining.value().empty() ? std::string{} : to_string(remaining.value().front()));

  auto next = addressSpace.create_namespace("urn:test:after-rejected-import", {});
  EXPECT_EQ(addressSpace.add_namespace_sync(std::move(next)), namespaceArrayBefore.size());

  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-COMP-SVR-NAMESPACE-METADATA-PUBLICATION-03-LIVE-IMMUTABLE, scope=function)
TEST_F(NamespaceMetadataPublicationTest, PublishedMetadataRejectsDifferentNodeSetDeclarationBeforeMutation)
{
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-nodeset-immutable", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);
  ASSERT_TRUE(import_metadata_nodeset(addressSpace, pool.get_executor(), importedMetadataNodeSet));

  const auto namespaceIndex =
    addressSpace.namespace_array().get_namespace_index("urn:test:imported-metadata");
  const auto namespaceArrayBefore = addressSpace.namespace_array().get_namespace_array();
  auto conflicting =
    import_metadata_nodeset(addressSpace, pool.get_executor(), conflictingImportedMetadataNodeSet);
  ASSERT_TRUE(conflicting.is_bad());
  EXPECT_EQ(conflicting.status_code(), Status::BadConfigurationError);
  ASSERT_NE(conflicting.shared_detail(), nullptr);
  EXPECT_EQ(conflicting.shared_detail()->code, "NamespaceMetadataDeclarationConflict");
  EXPECT_EQ(addressSpace.namespace_array().get_namespace_array(), namespaceArrayBefore);
  EXPECT_TRUE(addressSpace.try_find_node_sync(NodeId{namespaceIndex, 7100U}).is_bad());

  const auto metadataChildren = matching_children(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{namespaceIndex, "urn:test:imported-metadata"});
  ASSERT_EQ(metadataChildren.size(), 1U);
  EXPECT_EQ(metadataChildren.front(), NodeId(namespaceIndex, 7000U));
  auto version = read_property(addressSpace, metadataChildren.front(), "NamespaceVersion");
  ASSERT_TRUE(version);
  EXPECT_EQ(version.value().value().as<String>(), String{"document-version-one"});

  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-BASE-065-NAMESPACEMETADATA-BROWSENAME, scope=function)
// @relation(AC-SVR-BASE-066-NAMESPACEVERSION-NULL, scope=function)
// @relation(AC-SVR-BASE-067-PUBLICATIONDATE-NULL, scope=function)
// @relation(AC-SVR-BASE-068-ISNAMESPACESUBSET-DEFAULTS-TRUE, scope=function)
// @relation(AC-SVR-SECADMIN-046-DEFAULTROLEPERMISSIONS-PRESENT, scope=function)
// @relation(AC-SVR-SECADMIN-054-DEFAULTUSERROLEPERMISSIONS, scope=function)
// @relation(AC-SVR-AUTHZ-027-ABSENT-FACT-CLAIMS-NOTHING, scope=function)
TEST_F(NamespaceMetadataPublicationTest, StandardModelPublishesMandatoryCoreAndExactDefaults)
{
  auto& addressSpace = application_address_space();
  const auto namespaceIndex = application_namespace_index("urn:nmp-standard");
  const std::vector<RolePermissionType> defaults{permission(NodeId{ObjectId::WellKnownRole_Observer},
    PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  ASSERT_TRUE(prepare(
    addressSpace, {{namespaceIndex, String{"urn:nmp-standard"}, defaults, std::nullopt, std::nullopt}}));

  const auto metadata = unique_metadata_node(addressSpace, namespaceIndex, "urn:nmp-standard");
  auto namespaceUri = read_property(addressSpace, metadata, "NamespaceUri");
  ASSERT_TRUE(namespaceUri);
  ASSERT_TRUE(namespaceUri.value().value().is_string());
  EXPECT_EQ(namespaceUri.value().value().as<String>(), String{"urn:nmp-standard"});

  auto version = read_property(addressSpace, metadata, "NamespaceVersion");
  ASSERT_TRUE(version);
  ASSERT_TRUE(version.value().value().is_string());
  EXPECT_TRUE(version.value().value().as<String>().is_null());

  auto publicationDate = read_property(addressSpace, metadata, "NamespacePublicationDate");
  ASSERT_TRUE(publicationDate);
  ASSERT_TRUE(publicationDate.value().value().is_date_time());
  EXPECT_TRUE(publicationDate.value().value().as<DateTime>().is_null());

  auto subset = read_property(addressSpace, metadata, "IsNamespaceSubset");
  ASSERT_TRUE(subset);
  ASSERT_TRUE(subset.value().value().is_boolean());
  EXPECT_TRUE(subset.value().value().as<bool>());

  auto staticIdTypes = read_property(addressSpace, metadata, "StaticNodeIdTypes");
  ASSERT_TRUE(staticIdTypes);
  ASSERT_TRUE(staticIdTypes.value().value().is_array_of_int32());
  EXPECT_TRUE(staticIdTypes.value().value().as<Array<int32_t>>().empty());

  auto staticRanges = read_property(addressSpace, metadata, "StaticNumericNodeIdRange");
  ASSERT_TRUE(staticRanges);
  ASSERT_TRUE(staticRanges.value().value().is_array_of_string());
  EXPECT_TRUE(staticRanges.value().value().as<Array<String>>().empty());

  auto staticPattern = read_property(addressSpace, metadata, "StaticStringNodeIdPattern");
  ASSERT_TRUE(staticPattern);
  ASSERT_TRUE(staticPattern.value().value().is_string());
  EXPECT_TRUE(staticPattern.value().value().as<String>().is_null());
  auto configurationVersion = read_property(addressSpace, metadata, "ConfigurationVersion");
  ASSERT_TRUE(configurationVersion);
  ASSERT_TRUE(configurationVersion.value().value().is_uint32());
  EXPECT_GT(configurationVersion.value().value().as<uint32_t>(), 0u);

  auto defaultProperty = read_property(addressSpace, metadata, "DefaultRolePermissions");
  ASSERT_TRUE(defaultProperty);
  EXPECT_EQ(role_permissions(defaultProperty.value()), defaults);
  const auto defaultPropertyNode =
    addressSpace.find_node_sync(property_node_id(addressSpace, metadata, "DefaultRolePermissions"));
  const auto propertyPermissions = defaultPropertyNode.get_role_permissions();
  ASSERT_TRUE(propertyPermissions.has_value());
  ASSERT_EQ(propertyPermissions->size(), 1u);
  EXPECT_EQ(propertyPermissions->front().role_id(), NodeId{ObjectId::WellKnownRole_SecurityAdmin});
  EXPECT_TRUE(propertyPermissions->front().permissions().test(PermissionType::Bit::Read));
  EXPECT_TRUE(propertyPermissions->front().permissions().test(PermissionType::Bit::ReadRolePermissions));
  // Part 3 5.2.9 defines this Property as the Permissions for each Role assigned to the current
  // Session, so the answer is the caller's view, not the namespace's. An internal read presents no
  // identity, no Role is assigned to it, and the published array is therefore empty - the unfiltered
  // policy is on DefaultRolePermissions above, which is administrator-only.
  auto userDefaultProperty = read_property(addressSpace, metadata, "DefaultUserRolePermissions");
  ASSERT_TRUE(userDefaultProperty);
  EXPECT_TRUE(role_permissions(userDefaultProperty.value()).empty());

  // A Session holding the granted Role sees exactly the entry granted to it.
  const auto observer = publication_identity({NodeId{ObjectId::WellKnownRole_Observer}});
  auto observerView = read_property_as(addressSpace, metadata, "DefaultUserRolePermissions", observer);
  ASSERT_TRUE(observerView);
  EXPECT_EQ(role_permissions(observerView.value()), defaults);

  // A Session holding a Role the namespace grants nothing to sees an empty array, not the default.
  const auto engineer = publication_identity({NodeId{ObjectId::WellKnownRole_Engineer}});
  auto engineerView = read_property_as(addressSpace, metadata, "DefaultUserRolePermissions", engineer);
  ASSERT_TRUE(engineerView);
  EXPECT_TRUE(role_permissions(engineerView.value()).empty());
}

// @relation(AC-SVR-SECADMIN-056-VENDOR-MODEL-OMITS-DEFAULTS, scope=function)
// @relation(AC-SVR-ADDRSP-064-VENDOR-MODEL-OMITS-STANDARD-PROPERTIES, scope=function)
TEST_F(NamespaceMetadataPublicationTest, OpaqueNamespacesPublishCoreButNoStandardDefaults)
{
  auto& addressSpace = application_address_space();
  const auto vendorIndex = application_namespace_index("urn:nmp-vendor");
  const auto unspecifiedIndex = application_namespace_index("urn:nmp-unspecified");
  ASSERT_TRUE(prepare(addressSpace,
    {{vendorIndex, String{"urn:nmp-vendor"}, std::nullopt, std::nullopt, std::nullopt},
      {unspecifiedIndex, String{"urn:nmp-unspecified"}, std::nullopt, std::nullopt, std::nullopt}}));

  for (const auto& [index, uri] : std::array<std::pair<uint16_t, string_view>, 2>{
         {{vendorIndex, "urn:nmp-vendor"}, {unspecifiedIndex, "urn:nmp-unspecified"}}})
  {
    const auto metadata = unique_metadata_node(addressSpace, index, uri);
    EXPECT_EQ(matching_children(addressSpace,
                metadata,
                NodeId{ReferenceTypeId::HasProperty},
                QualifiedName{0, "DefaultRolePermissions"})
                .size(),
      0u);
    EXPECT_EQ(matching_children(addressSpace,
                metadata,
                NodeId{ReferenceTypeId::HasProperty},
                QualifiedName{0, "DefaultUserRolePermissions"})
                .size(),
      0u);
    auto namespaceUri = read_property(addressSpace, metadata, "NamespaceUri");
    ASSERT_TRUE(namespaceUri);
    EXPECT_EQ(namespaceUri.value().value().as<String>(), String{uri});
    auto configurationVersion = read_property(addressSpace, metadata, "ConfigurationVersion");
    ASSERT_TRUE(configurationVersion);
    ASSERT_TRUE(configurationVersion.value().value().is_uint32());
    EXPECT_GT(configurationVersion.value().value().as<uint32_t>(), 0u);
  }
}

// Part 3 section 8.58 requires the related NamespaceMetadata.ConfigurationVersion to move after
// every successful Value change on a Variable whose AccessLevelEx.Constant bit is set.
// @relation(AC-SVR-ADDRSP-237-CONSTANT-BUMPS-VERSION, scope=function)
TEST_F(NamespaceMetadataPublicationTest, ConstantValueWriteAdvancesRelatedConfigurationVersion)
{
  auto& addressSpace = application_address_space();
  const auto namespaceIndex = application_namespace_index("urn:nmp-constant");
  ASSERT_TRUE(prepare(
    addressSpace, {{namespaceIndex, String{"urn:nmp-constant"}, std::nullopt, std::nullopt, std::nullopt}}));

  const auto metadata = unique_metadata_node(addressSpace, namespaceIndex, "urn:nmp-constant");
  const auto versionIds = matching_children(
    addressSpace, metadata, NodeId{ReferenceTypeId::HasProperty}, QualifiedName{0, "ConfigurationVersion"});
  ASSERT_EQ(versionIds.size(), 1u);
  auto before = read_property(addressSpace, metadata, "ConfigurationVersion");
  ASSERT_TRUE(before);
  const auto beforeValue = before.value().value().as<uint32_t>();

  const NodeId variableId{namespaceIndex, uint32_t{7110}};
  auto variableResult = addressSpace.try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
  ASSERT_TRUE(variableResult);
  auto& variable = variableResult.value();
  variable.write_value_sync(int32_t{1});
  variable.set_access_level_ex(
    AccessLevelExType{AccessLevelExType::Bit::CurrentRead, AccessLevelExType::Bit::Constant});

  ASSERT_TRUE(variable.try_write_value_sync(int32_t{2}));
  auto after = read_property(addressSpace, metadata, "ConfigurationVersion");
  ASSERT_TRUE(after);
  EXPECT_GT(after.value().value().as<uint32_t>(), beforeValue);
}

// @relation(AC-SVR-ADDRSP-237-CONSTANT-BUMPS-VERSION, scope=function)
TEST_F(NamespaceMetadataPublicationTest, ConstantValueWritePreservesConfigurationVersionTypeErrorDetail)
{
  auto& addressSpace = application_address_space();
  const auto namespaceIndex = application_namespace_index("urn:nmp-constant");
  ASSERT_TRUE(prepare(
    addressSpace, {{namespaceIndex, String{"urn:nmp-constant"}, std::nullopt, std::nullopt, std::nullopt}}));
  const auto metadata = unique_metadata_node(addressSpace, namespaceIndex, "urn:nmp-constant");
  const auto versionIds = matching_children(
    addressSpace, metadata, NodeId{ReferenceTypeId::HasProperty}, QualifiedName{0, "ConfigurationVersion"});
  ASSERT_EQ(versionIds.size(), 1u);
  auto version = addressSpace.try_find_sync<VariableAccessor>(versionIds.front());
  ASSERT_TRUE(version);
  const auto originalVersion = version.value().read_value_sync();
  version.value().write_value_sync(String{"not-a-VersionTime"});

  const NodeId variableId{namespaceIndex, uint32_t{7111}};
  auto variable = addressSpace.try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
  ASSERT_TRUE(variable);
  variable.value().write_value_sync(int32_t{1});
  variable.value().set_access_level_ex(
    AccessLevelExType{AccessLevelExType::Bit::CurrentRead, AccessLevelExType::Bit::Constant});

  const auto result = variable.value().try_write_value_sync(int32_t{2});
  EXPECT_TRUE(result.is_bad());
  if (result.is_bad())
  {
    EXPECT_EQ(result.status_code().as_status(), Status::BadTypeMismatch);
    EXPECT_NE(result.shared_detail(), nullptr);
    if (result.shared_detail())
    {
      EXPECT_EQ(result.shared_detail()->code, "ConfigurationVersionTypeMismatch");
    }
  }
  version.value().write_value_sync(originalVersion);
}

// Part 3 section 8.58: each change of a Constant Variable's Value triggers a change of ConfigurationVersion.
// Changes made while an advance runs are covered by the next one, so several concurrent writes may share one
// advance; each write answers only after an advance that started after its change.
// @relation(AC-SVR-ADDRSP-237-CONSTANT-BUMPS-VERSION, scope=function)
TEST_F(NamespaceMetadataPublicationTest, ConcurrentConstantWritesEachAnswerAfterAnAdvance)
{
  auto& addressSpace = application_address_space();
  const auto namespaceIndex = application_namespace_index("urn:nmp-constant");
  ASSERT_TRUE(prepare(
    addressSpace, {{namespaceIndex, String{"urn:nmp-constant"}, std::nullopt, std::nullopt, std::nullopt}}));
  const auto metadata = unique_metadata_node(addressSpace, namespaceIndex, "urn:nmp-constant");
  auto before = read_property(addressSpace, metadata, "ConfigurationVersion");
  ASSERT_TRUE(before);
  const auto beforeValue = before.value().value().as<uint32_t>();

  const NodeId variableId{namespaceIndex, uint32_t{7112}};
  auto variable = addressSpace.try_create_sync<VariableAccessor>(variableId, NodeClass::Variable);
  ASSERT_TRUE(variable);
  variable.value().write_value_sync(int32_t{1});
  variable.value().set_access_level_ex(
    AccessLevelExType{AccessLevelExType::Bit::CurrentRead, AccessLevelExType::Bit::Constant});

  constexpr size_t writerCount = 8;
  std::atomic<size_t> successes{0};
  // Writes that answered while ConfigurationVersion still held the value read before any of them.
  std::atomic<size_t> answeredBeforeAnAdvance{0};
  std::vector<std::thread> writers;
  writers.reserve(writerCount);
  for (size_t index = 0; index < writerCount; ++index)
  {
    writers.emplace_back(
      [&, index]
      {
        if (!variable.value().try_write_value_sync(static_cast<int32_t>(index + 2U)).is_good())
        {
          return;
        }
        successes.fetch_add(1, std::memory_order_relaxed);
        auto seen = read_property(addressSpace, metadata, "ConfigurationVersion");
        if (!seen || seen.value().value().as<uint32_t>() <= beforeValue)
        {
          answeredBeforeAnAdvance.fetch_add(1, std::memory_order_relaxed);
        }
      });
  }
  for (auto& writer : writers)
  {
    writer.join();
  }

  EXPECT_EQ(successes.load(std::memory_order_relaxed), writerCount);
  EXPECT_EQ(answeredBeforeAnAdvance.load(std::memory_order_relaxed), 0u)
    << "a Constant write answered before ConfigurationVersion advanced past the value it had before the "
       "writes";
  auto after = read_property(addressSpace, metadata, "ConfigurationVersion");
  ASSERT_TRUE(after);
  EXPECT_GT(after.value().value().as<uint32_t>(), beforeValue);
}

// Part 4 section 7.44 requires each updated VersionTime to be greater than its predecessor. The
// allocator is shared by startup flows, so even namespaces initialized in the same clock second get
// distinct, strictly increasing values.
// @relation(AC-SVR-ADDRSP-238-CONSTANT-VOLATILE-BUMPS-ON-RESTART, scope=function)
TEST_F(NamespaceMetadataPublicationTest, StartupConfigurationVersionsAreStrictlyIncreasing)
{
  auto& addressSpace = application_address_space();
  const auto firstIndex = application_namespace_index("urn:nmp-version-first");
  const auto secondIndex = application_namespace_index("urn:nmp-version-second");
  ASSERT_TRUE(prepare(addressSpace,
    {{firstIndex, String{"urn:nmp-version-first"}, std::nullopt, std::nullopt, std::nullopt},
      {secondIndex, String{"urn:nmp-version-second"}, std::nullopt, std::nullopt, std::nullopt}}));

  const auto firstMetadata = unique_metadata_node(addressSpace, firstIndex, "urn:nmp-version-first");
  const auto secondMetadata = unique_metadata_node(addressSpace, secondIndex, "urn:nmp-version-second");
  auto first = read_property(addressSpace, firstMetadata, "ConfigurationVersion");
  auto second = read_property(addressSpace, secondMetadata, "ConfigurationVersion");
  ASSERT_TRUE(first);
  ASSERT_TRUE(second);
  EXPECT_GT(second.value().value().as<uint32_t>(), first.value().value().as<uint32_t>());
}

// @relation(AC-SVR-ADDRSP-056-NAMESPACE-METADATA-PREPARATION-IDEMPOTENT, scope=function)
TEST_F(NamespaceMetadataPublicationTest, RepeatedPreparationDoesNotDuplicateObjectsOrProperties)
{
  auto& addressSpace = application_address_space();
  const auto namespaceIndex = application_namespace_index("urn:nmp-idempotent");
  const std::vector<RolePermissionType> defaults{
    permission(NodeId{ObjectId::WellKnownRole_Operator}, PermissionType{PermissionType::Bit::Browse})};
  const NamespaceMetadataSnapshot snapshot{
    namespaceIndex, String{"urn:nmp-idempotent"}, defaults, std::nullopt, std::nullopt};

  ASSERT_TRUE(prepare(addressSpace, {snapshot}));
  const auto metadataBefore = unique_metadata_node(addressSpace, namespaceIndex, "urn:nmp-idempotent");
  const auto valueBefore = read_property(addressSpace, metadataBefore, "DefaultRolePermissions");
  ASSERT_TRUE(valueBefore);

  ASSERT_TRUE(prepare(addressSpace, {snapshot}));
  const auto metadataMatches = matching_children(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{namespaceIndex, "urn:nmp-idempotent"});
  ASSERT_EQ(metadataMatches.size(), 1u);
  EXPECT_EQ(metadataMatches.front(), metadataBefore);

  for (const auto propertyName : std::array<string_view, 11>{"NamespaceUri",
         "NamespaceVersion",
         "NamespacePublicationDate",
         "IsNamespaceSubset",
         "StaticNodeIdTypes",
         "StaticNumericNodeIdRange",
         "StaticStringNodeIdPattern",
         "ConfigurationVersion",
         "DefaultRolePermissions",
         "DefaultUserRolePermissions",
         "DefaultAccessRestrictions"})
  {
    EXPECT_EQ(
      matching_children(
        addressSpace, metadataBefore, NodeId{ReferenceTypeId::HasProperty}, QualifiedName{0, propertyName})
        .size(),
      1u)
      << propertyName;
  }
  const auto valueAfter = read_property(addressSpace, metadataBefore, "DefaultRolePermissions");
  ASSERT_TRUE(valueAfter);
  EXPECT_EQ(valueAfter.value().value(), valueBefore.value().value());
}

// The three tests below replace StoredRoleArrayIsNotServed, UserPropertyAnswerIsFilteredPerIdentity and
// GoverningRestrictionAnswersComeFromTheNamespaceInterface, which drove
// NamespaceMetadataPublication::answer() - the central per-value substitution that no longer exists.
// Each claim they made that survives the redesign is re-armed here against the mechanism that replaced
// it. One claim does not survive: "the stored array is not served" described a design in which a table
// recomputed the published value on every read, so there was a stored array to disagree with. The
// published array is now the one the server enforces, which is the claim worth proving, and
// PublishedDefaultsAreWhatIsEnforced proves it directly.

// @relation(AC-SVR-AUTHZ-024-PUBLISHED-IS-ENFORCED, scope=function)
TEST_F(NamespaceMetadataPublicationTest, PublishedDefaultsAreWhatIsEnforced)
{
  // Its own AddressSpace, registered through the coordinator, so the array published on the Property and
  // the array AccessControl evaluates both come from this namespace's default_role_permissions(). Handing
  // `prepare` a snapshot the namespace does not hold would let the test pass while the two disagree,
  // which is the one thing it is here to rule out.
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-enforced-host", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);

  const std::vector<RolePermissionType> defaults{permission(NodeId{ObjectId::WellKnownRole_Observer},
    PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read})};
  const auto namespaceIndex =
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:nmp-enforced", defaults));

  const auto metadata = unique_metadata_node(addressSpace, namespaceIndex, "urn:nmp-enforced");
  auto published = read_property(addressSpace, metadata, "DefaultRolePermissions");
  ASSERT_TRUE(published);
  ASSERT_EQ(role_permissions(published.value()), defaults);

  // A node of the described namespace carrying no RolePermissions of its own falls back to the namespace
  // default (Part 3 4.8.3). Browse and Read are granted to the Role the published array names; Write,
  // which that array does not grant, is refused to it; and a Role the array does not name gets nothing.
  const NodeId undecoratedNodeId{namespaceIndex, 9100u};
  auto undecorated = addressSpace.try_create_node_sync(undecoratedNodeId, NodeClass::Variable, {});
  ASSERT_TRUE(undecorated.is_good()) << undecorated.status_code().as_uint32();

  AccessControl accessControl{addressSpace, std::chrono::milliseconds{100}};
  const auto observer = publication_identity({NodeId{ObjectId::WellKnownRole_Observer}});
  const auto engineer = publication_identity({NodeId{ObjectId::WellKnownRole_Engineer}});
  EXPECT_TRUE(authorize_one(accessControl, observer, undecorated.value(), AccessOperation::Browse).permitted);
  EXPECT_TRUE(authorize_one(accessControl, observer, undecorated.value(), AccessOperation::Read).permitted);
  // Bad_UserAccessDenied is the refusal the criterion names, so observe the cause and not just the bool.
  const auto writeRefused =
    authorize_one(accessControl, observer, undecorated.value(), AccessOperation::Write);
  EXPECT_FALSE(writeRefused.permitted);
  EXPECT_EQ(writeRefused.cause, StatusCode{Status::BadUserAccessDenied});
  const auto browseRefused =
    authorize_one(accessControl, engineer, undecorated.value(), AccessOperation::Browse);
  EXPECT_FALSE(browseRefused.permitted);
  EXPECT_EQ(browseRefused.cause, StatusCode{Status::BadUserAccessDenied});

  // A node merely *named* DefaultRolePermissions gets no projection: the redesign removed the per-value
  // lookup, so there is no name or NodeId that makes AccessControl substitute a value. An ordinary array
  // Value passes through it unchanged.
  const NodeId decoyNodeId{namespaceIndex, 9101u};
  auto decoy = addressSpace.try_create_node_sync(decoyNodeId, NodeClass::Variable, {});
  ASSERT_TRUE(decoy.is_good());
  decoy.value().set_browse_name(QualifiedName{0, "DefaultRolePermissions"});
  decoy.value().set_role_permissions(defaults);

  Array<String> ordinaryArray;
  ordinaryArray.payload().push_back(String{"preserved"});
  const auto ordinaryVerdict = authorize_one(accessControl, observer, decoy.value(), AccessOperation::Read);
  const auto ordinaryValue = accessControl.make_client_attribute_value(observer,
    decoy.value(),
    AttributeId::Value,
    DataValue{Variant{std::move(ordinaryArray)}, StatusCode{Status::Good}},
    ordinaryVerdict,
    observer.endpoint());
  ASSERT_FALSE(ordinaryValue.status() && ordinaryValue.status()->is_bad());
  ASSERT_TRUE(ordinaryValue.value().is_array());
  ASSERT_EQ(ordinaryValue.value().as<Array<String>>().size(), 1u);
  EXPECT_EQ(ordinaryValue.value().as<Array<String>>()[0], String{"preserved"});

  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-AUTHZ-024-USER-PROPERTY-IS-PER-SESSION-AND-OMITTED, scope=function)
TEST_F(NamespaceMetadataPublicationTest, UserPropertyAnswerIsFilteredPerIdentity)
{
  // Its own AddressSpace: the suite shares one, so a namespace another test has already published would
  // be adopted here rather than created, and an adopted Object keeps the values and handlers it already
  // has - which would make this test's result depend on which tests ran before it.
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-user-filter-host", pool.get_executor());
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
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:nmp-user-filter", defaults));
  const auto metadata = unique_metadata_node(addressSpace, namespaceIndex, "urn:nmp-user-filter");

  // Part 3 5.2.9 defines the value as the Permissions for each Role assigned to the current Session, so
  // two Sessions of the same server read different arrays from the same node - and each reads only its
  // own entry, not the whole default beside it.
  const auto observer = publication_identity({NodeId{ObjectId::WellKnownRole_Observer}});
  const auto operatorIdentity = publication_identity({NodeId{ObjectId::WellKnownRole_Operator}});
  auto observerAnswer = read_property_as(addressSpace, metadata, "DefaultUserRolePermissions", observer);
  auto operatorAnswer =
    read_property_as(addressSpace, metadata, "DefaultUserRolePermissions", operatorIdentity);
  ASSERT_TRUE(observerAnswer);
  ASSERT_TRUE(operatorAnswer);
  EXPECT_EQ(role_permissions(observerAnswer.value()), std::vector<RolePermissionType>{observerEntry});
  EXPECT_EQ(role_permissions(operatorAnswer.value()), std::vector<RolePermissionType>{operatorEntry});

  // A Session holding both Roles reads both entries, so the filter selects rather than truncates.
  const auto both = publication_identity(
    {NodeId{ObjectId::WellKnownRole_Operator}, NodeId{ObjectId::WellKnownRole_Observer}});
  auto bothAnswer = read_property_as(addressSpace, metadata, "DefaultUserRolePermissions", both);
  ASSERT_TRUE(bothAnswer);
  EXPECT_EQ(role_permissions(bothAnswer.value()), defaults);

  // A Session holding a Role the namespace grants nothing to reads an empty array, and so does a
  // caller presenting no identity at all. Neither is given the array published beside it.
  const auto engineer = publication_identity({NodeId{ObjectId::WellKnownRole_Engineer}});
  auto engineerAnswer = read_property_as(addressSpace, metadata, "DefaultUserRolePermissions", engineer);
  ASSERT_TRUE(engineerAnswer);
  EXPECT_TRUE(role_permissions(engineerAnswer.value()).empty());
  auto anonymousAnswer = read_property(addressSpace, metadata, "DefaultUserRolePermissions");
  ASSERT_TRUE(anonymousAnswer);
  EXPECT_TRUE(role_permissions(anonymousAnswer.value()).empty());

  // The administrator view is unaffected by who reads the user view beside it.
  auto adminView = read_property(addressSpace, metadata, "DefaultRolePermissions");
  ASSERT_TRUE(adminView);
  EXPECT_EQ(role_permissions(adminView.value()), defaults);

  ::ua::test_utils::drain_with_timeout(pool);
}

// The per-Session cache-disclosure guard that stood here has been removed with the mechanism it
// guarded. `default_ns::VariableNode` no longer keeps a per-node copy of a value its source produced,
// so there is nothing for an unbounded `maxAge` to serve from and the test could no longer fail. The
// claim it made is carried by
// ReadServiceRequirements.ATTR_READ_003_MaxAgeReachesTheValueSourceUnalteredAndItsAnswerStands, whose
// third conjunct proves a source is asked again on every Read rather than answered on its behalf -
// which fails immediately if a cache is ever reintroduced, for per-caller and ordinary values alike.

// @relation(AC-SVR-AUTHZ-028-NO-CONDITION-PUBLISHES-EMPTY-NOT-ABSENT, scope=function)
TEST_F(NamespaceMetadataPublicationTest, NoChannelConditionPublishesTheEmptyMaskNotAnAbsentProperty)
{
  // Its own AddressSpace rather than the suite's: the suite's is shared across tests, so a namespace an
  // earlier test has published is adopted rather than created, and an adopted Object keeps the values it
  // already serves. Registering through the coordinator here also exercises the whole chain - the
  // namespace's own default_access_restrictions() reaching the published Property - rather than a
  // snapshot built by hand in the test.
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-restriction-host", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto publication = NamespaceMetadataPublication::create(addressSpace);
  NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, publication);

  const auto restrictedIndex =
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:nmp-encrypted",
      std::vector<RolePermissionType>{},
      AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired}));
  // Left at the SDK default, which declares no channel condition.
  const auto unrestrictedIndex =
    addressSpace.add_namespace_sync(addressSpace.create_namespace("urn:nmp-unconditioned", {}));

  // Part 3 5.2.11: a namespace declaring a channel condition publishes it.
  const auto restrictedMetadata = unique_metadata_node(addressSpace, restrictedIndex, "urn:nmp-encrypted");
  auto restricted = read_property(addressSpace, restrictedMetadata, "DefaultAccessRestrictions");
  ASSERT_TRUE(restricted);
  ASSERT_TRUE(restricted.value().value().is_uint16());
  EXPECT_EQ(restricted.value().value().as<uint16_t>(),
    AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired}.as_underlying_type());

  // A namespace imposing no condition publishes the zero mask. The Property is present and reads good:
  // an absent Property would say the server has no position on the channel, which is a different claim
  // from "no condition applies", and a client cannot tell those apart from a Bad status.
  const auto unrestrictedMetadata =
    unique_metadata_node(addressSpace, unrestrictedIndex, "urn:nmp-unconditioned");
  EXPECT_EQ(matching_children(addressSpace,
              unrestrictedMetadata,
              NodeId{ReferenceTypeId::HasProperty},
              QualifiedName{0, "DefaultAccessRestrictions"})
              .size(),
    1u);
  auto unrestricted = read_property(addressSpace, unrestrictedMetadata, "DefaultAccessRestrictions");
  ASSERT_TRUE(unrestricted);
  ASSERT_TRUE(unrestricted.value().value().is_uint16());
  EXPECT_EQ(unrestricted.value().value().as<uint16_t>(), 0u);

  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-AUTHZ-028-OPAQUE-AND-PUBLISHING-IS-REFUSED, scope=function)
TEST_F(NamespaceMetadataPublicationTest, OpaqueNamespacePublishingARoleArrayRefusesPreparation)
{
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-opaque", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto opaqueNamespace = addressSpace.create_namespace("urn:nmp-opaque-owner", {});
  const auto namespaceIndex = addressSpace.add_namespace_sync(opaqueNamespace);

  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::HasComponent};
  options.targetNamespaceIndex = namespaceIndex;
  options.nodeIdAllocator = guid_node_id_allocator();
  options.optionalChildFilter = [](const ChildFilterInfo& child)
  {
    if (child.browseName == QualifiedName{0, "DefaultRolePermissions"})
    {
      return true;
    }
    return child.browseName == QualifiedName{0, "DefaultAccessRestrictions"};
  };
  auto metadata = NamespaceMetadata::create_sync(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    QualifiedName{namespaceIndex, "OpaqueMetadata"},
    options);
  const auto metadataId = metadata.node_id();
  auto namespaceUri = metadata.namespace_uri_property_sync();
  DataValue correctUriValue;
  correctUriValue.value() = Variant{String{"urn:nmp-opaque-owner"}};
  namespaceUri.write_value_sync(std::move(correctUriValue));
  const auto rolePropertyId = metadata.default_role_permissions_property_sync().node_id();
  metadata.release();

  const NamespaceMetadataSnapshot snapshot{
    namespaceIndex, String{"urn:nmp-opaque-owner"}, std::nullopt, std::nullopt, metadataId};
  auto refused = prepare_publication(addressSpace, {snapshot}).second;
  ASSERT_TRUE(refused.is_bad());
  ASSERT_NE(refused.shared_detail(), nullptr);
  EXPECT_EQ(refused.shared_detail()->code, "NamespaceMetadataOpaqueRoleProperty");
  EXPECT_EQ(::ua::test_utils::error_context(refused.shared_detail().get(), ContextKeys::namespaceUri.value()),
    "urn:nmp-opaque-owner");

  auto metadataNode = addressSpace.find_node_sync(metadataId);
  ASSERT_TRUE(
    metadataNode.try_remove_reference_sync(NodeId{ReferenceTypeId::HasProperty}, rolePropertyId, true));
  auto accepted = prepare_publication(addressSpace, {snapshot}).second;
  if (accepted.is_bad() && accepted.shared_detail())
  {
    ADD_FAILURE() << accepted.shared_detail()->code;
  }
  ASSERT_TRUE(accepted) << accepted.status_code().as_uint32();
  EXPECT_TRUE(matching_children(addressSpace,
    metadataId,
    NodeId{ReferenceTypeId::HasProperty},
    QualifiedName{0, "DefaultRolePermissions"})
                .empty());
  EXPECT_TRUE(matching_children(addressSpace,
    metadataId,
    NodeId{ReferenceTypeId::HasProperty},
    QualifiedName{0, "DefaultUserRolePermissions"})
                .empty());

  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(AC-SVR-AUTHZ-029-BAD-DECLARATION-FAILS-START, scope=function)
// @relation(AC-SVR-AUTHZ-026-ADOPTED-OBJECT-IS-NOT-DUPLICATED, scope=function)
TEST_F(NamespaceMetadataPublicationTest, BadDeclarationRefusesPreparationWithAnActionableCause)
{
  boost::asio::thread_pool pool;
  AddressSpace addressSpace = AddressSpace::create("urn:nmp-declaration", pool.get_executor());
  StructureFactory structureFactory;
  load_ns0(addressSpace, structureFactory);
  auto declaredNamespace = addressSpace.create_namespace("urn:nmp-declared-owner", {});
  const auto namespaceIndex = addressSpace.add_namespace_sync(declaredNamespace);

  auto prepareDeclared = [&](const NodeId& declared)
  {
    return prepare_publication(addressSpace,
      {{namespaceIndex,
        String{"urn:nmp-declared-owner"},
        std::vector<RolePermissionType>{},
        std::nullopt,
        declared}})
      .second;
  };

  auto foreign = prepareDeclared(NodeId{uint16_t{1}, 7000U});
  ASSERT_TRUE(foreign.is_bad());
  ASSERT_NE(foreign.shared_detail(), nullptr);
  EXPECT_EQ(foreign.shared_detail()->code, "NamespaceMetadataForeignNode");

  auto unresolvable = prepareDeclared(NodeId{namespaceIndex, 7001U});
  ASSERT_TRUE(unresolvable.is_bad());
  ASSERT_NE(unresolvable.shared_detail(), nullptr);
  EXPECT_EQ(unresolvable.shared_detail()->code, "NamespaceMetadataUnresolvable");

  const NodeId wrongTypeId{namespaceIndex, 7002U};
  ASSERT_TRUE(addressSpace.try_create_node_sync(wrongTypeId, NodeClass::Object, {}));
  auto wrongType = prepareDeclared(wrongTypeId);
  ASSERT_TRUE(wrongType.is_bad());
  ASSERT_NE(wrongType.shared_detail(), nullptr);
  EXPECT_EQ(wrongType.shared_detail()->code, "NamespaceMetadataWrongType");

  InstantiationOptions options;
  options.parentReferenceType = NodeId{ReferenceTypeId::HasComponent};
  options.targetNamespaceIndex = namespaceIndex;
  options.nodeIdAllocator = guid_node_id_allocator();
  auto metadata = NamespaceMetadata::create_sync(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    QualifiedName{namespaceIndex, "DeclaredMetadata"},
    options);
  const auto metadataId = metadata.node_id();
  auto namespaceUri = metadata.namespace_uri_property_sync();
  DataValue wrongUriValue;
  wrongUriValue.value() = Variant{String{"urn:different-namespace"}};
  namespaceUri.write_value_sync(std::move(wrongUriValue));
  metadata.release();

  auto wrongUri = prepareDeclared(metadataId);
  ASSERT_TRUE(wrongUri.is_bad());
  ASSERT_NE(wrongUri.shared_detail(), nullptr);
  EXPECT_EQ(wrongUri.shared_detail()->code, "NamespaceMetadataUriMismatch");

  DataValue correctUriValue;
  correctUriValue.value() = Variant{String{"urn:nmp-declared-owner"}};
  namespaceUri.write_value_sync(std::move(correctUriValue));
  auto namespacesParent = addressSpace.find_node_sync(NodeId{ObjectId::Server_Namespaces});
  ASSERT_TRUE(
    namespacesParent.try_remove_reference_sync(NodeId{ReferenceTypeId::HasComponent}, metadataId, true));
  auto accepted = prepareDeclared(metadataId);
  ASSERT_TRUE(accepted);
  const auto matches = matching_children(addressSpace,
    NodeId{ObjectId::Server_Namespaces},
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{namespaceIndex, "DeclaredMetadata"});
  ASSERT_EQ(matches.size(), 1u);
  EXPECT_EQ(matches.front(), metadataId);

  ::ua::test_utils::drain_with_timeout(pool);
}

// A refused value-source installation must retain the namespace's rich cause, including
// when preparation adopts a real metadata object that the namespace already owns.
TEST_F(NamespaceMetadataPublicationTest, UserProjectionInstallFailurePreservesRichCauseAndAdoptedProperty)
{
  auto callbackCount = std::make_shared<std::atomic<size_t>>(0);
  const auto drainPool = [](boost::asio::thread_pool* ownedPool)
  {
    ::ua::test_utils::drain_with_timeout(*ownedPool);
    delete ownedPool;
  };
  std::unique_ptr<boost::asio::thread_pool, decltype(drainPool)> pool{
    new boost::asio::thread_pool{1}, drainPool};
  {
    std::optional<AddressSpace> addressSpace{
      AddressSpace::create("urn:nmp-projection-host", pool->get_executor())};
    StructureFactory structureFactory;
    load_ns0(*addressSpace, structureFactory);
    const String uri{"urn:nmp-projection-refusal"};
    const StatusCode nested{Status::BadNotSupported,
      ErrorDetail::build("ProjectionRefusalCause", "The namespace refused projection support", "test")};
    const StatusCode injected{Status::BadResourceUnavailable,
      ErrorDetail::build("InjectedProjectionInstallFailure",
        "The test property refused its value source",
        "PostingWritesNamespace")
        .cause(nested)};
    const auto injectedDetail = injected.shared_detail();
    ASSERT_NE(injectedDetail, nullptr);
    ASSERT_EQ(injectedDetail->cause, nested.shared_detail());
    auto nameSpace = ua::test::PostingWritesNamespace::create(static_cast<string_view>(uri),
      pool->get_executor(),
      ua::test::PostingWritesNamespace::CallHandlers::Accepted,
      ua::test::PostingWritesNamespace::ValueSources::Refused,
      injected);
    const auto namespaceIndex = addressSpace->add_namespace_sync(nameSpace);

    // Both the creation result and a later lookup must retain the configured refusal.
    const NodeId probeId{namespaceIndex, 9001u};
    auto createdProbe = addressSpace->create_node_sync(probeId, NodeClass::Variable);
    ASSERT_NE(createdProbe->external_value_source(), nullptr);
    const auto createdRefusal = createdProbe->external_value_source()->set_value_source(nullptr);
    EXPECT_EQ(createdRefusal.status_code().as_status(), injected.as_status());
    EXPECT_EQ(createdRefusal.shared_detail(), injectedDetail);
    auto lookedUpProbe = addressSpace->find_node_sync(probeId);
    ASSERT_NE(lookedUpProbe->external_value_source(), nullptr);
    const auto lookupRefusal = lookedUpProbe->external_value_source()->set_value_source(nullptr);
    EXPECT_EQ(lookupRefusal.status_code().as_status(), injected.as_status());
    EXPECT_EQ(lookupRefusal.shared_detail(), injectedDetail);

    InstantiationOptions options;
    options.parentReferenceType = NodeId{ReferenceTypeId::HasComponent};
    options.targetNamespaceIndex = namespaceIndex;
    options.nodeIdAllocator = guid_node_id_allocator();
    options.optionalChildFilter = [](const ChildFilterInfo& child)
    {
      return child.browseName == QualifiedName{0, "ConfigurationVersion"} ||
             child.browseName == QualifiedName{0, "DefaultRolePermissions"} ||
             child.browseName == QualifiedName{0, "DefaultUserRolePermissions"} ||
             child.browseName == QualifiedName{0, "DefaultAccessRestrictions"};
    };
    auto metadata = NamespaceMetadata::create_sync(*addressSpace,
      NodeId{ObjectId::Server_Namespaces},
      QualifiedName{namespaceIndex, "DeclaredProjectionMetadata"},
      options);
    const auto metadataId = metadata.node_id();
    auto uriProperty = metadata.namespace_uri_property_sync();
    DataValue uriValue;
    uriValue.value() = Variant{uri};
    uriProperty.write_value_sync(std::move(uriValue));
    const auto userPropertyId = property_node_id(*addressSpace, metadataId, "DefaultUserRolePermissions");
    ASSERT_NE(userPropertyId, NodeId{});
    auto userProperty = addressSpace->find_node_sync(userPropertyId);
    ASSERT_NE(userProperty->external_value_source(), nullptr);
    auto restrictions = metadata.default_access_restrictions_property_sync();
    DataValue untouched;
    untouched.value() = Variant{uint16_t{0}};
    restrictions.write_value_sync(std::move(untouched));
    metadata.release();
    const auto samplingWrites = nameSpace->posted_writes(AttributeId::MinimumSamplingInterval);

    auto publication = NamespaceMetadataPublication::create(*addressSpace);
    auto answered = std::make_shared<std::promise<VoidResult>>();
    auto future = answered->get_future();
    publication->prepare_async(
      {{namespaceIndex,
        uri,
        std::vector<RolePermissionType>{permission(NodeId{ObjectId::WellKnownRole_Observer},
          PermissionType{PermissionType::Bit::Browse, PermissionType::Bit::Read})},
        AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired},
        metadataId}},
      [answered, callbackCount](VoidResult result)
      {
        if (callbackCount->fetch_add(1) == 0)
          answered->set_value(std::move(result));
      });
    ASSERT_EQ(future.wait_for(std::chrono::seconds{10}), std::future_status::ready);
    const auto result = future.get();
    ASSERT_TRUE(result.is_bad());
    EXPECT_EQ(result.status_code().as_status(), injected.as_status());
    ASSERT_NE(result.shared_detail(), nullptr);
    const auto detail = result.shared_detail();
    EXPECT_EQ(detail->code, "NamespaceMetadataUserPropertyNotProjectable");
    EXPECT_EQ(detail->source, "NamespaceMetadataPublication");
    EXPECT_EQ(
      ::ua::test_utils::error_context(detail.get(), ContextKeys::namespaceUri.value()), std::string{uri});
    EXPECT_EQ(
      ::ua::test_utils::error_context(detail.get(), ContextKeys::nodeId.value()), to_string(userPropertyId));
    EXPECT_EQ(detail->innerStatus, injected.value());
    EXPECT_EQ(detail->cause, injectedDetail);

    EXPECT_TRUE(addressSpace->try_find_node_sync(metadataId).is_good());
    EXPECT_TRUE(addressSpace->try_find_node_sync(userPropertyId).is_good());
    EXPECT_EQ(matching_children(*addressSpace,
                metadataId,
                NodeId{ReferenceTypeId::HasProperty},
                QualifiedName{0, "DefaultUserRolePermissions"}),
      std::vector<NodeId>{userPropertyId});
    EXPECT_EQ(matching_children(*addressSpace,
                NodeId{ObjectId::Server_Namespaces},
                NodeId{ReferenceTypeId::HasComponent},
                QualifiedName{namespaceIndex, "DeclaredProjectionMetadata"}),
      std::vector<NodeId>{metadataId});
    const auto publishedUri = read_property(*addressSpace, metadataId, "NamespaceUri");
    ASSERT_TRUE(publishedUri.is_good());
    EXPECT_EQ(publishedUri.value().value().as<String>(), uri);
    EXPECT_EQ(nameSpace->posted_writes(AttributeId::MinimumSamplingInterval), samplingWrites)
      << "the success-only sampling write must not follow a refused projection installation";
    const auto accessRestrictions = read_property(*addressSpace, metadataId, "DefaultAccessRestrictions");
    ASSERT_TRUE(accessRestrictions.is_good());
    EXPECT_EQ(accessRestrictions.value().value().as<uint16_t>(), 0u)
      << "preparation must not write a later Property after refusing the projection";
  }
  pool.reset();
  EXPECT_EQ(callbackCount->load(), 1u);
}

// @relation(AC-SVR-DIAG-001-NAMESPACE-METADATA-PREPARATION, scope=function)
TEST_F(NamespaceMetadataPublicationTest, MissingNamespacesParentPreservesRichFailureAndCompletesOnce)
{
  boost::asio::thread_pool pool;
  std::optional<AddressSpace> addressSpace{
    AddressSpace::create("urn:nmp-missing-parent", pool.get_executor())};
  auto before = enumerate_nodes(*addressSpace, uint16_t{1});
  ASSERT_TRUE(before);
  std::atomic<size_t> callbackCount{0};

  auto result = prepare(*addressSpace,
    {{uint16_t{1}, String{"urn:nmp-missing-parent"}, std::nullopt, std::nullopt, std::nullopt}},
    &callbackCount);

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "NamespaceMetadataParentUnavailable");
  EXPECT_EQ(StatusCode{result.shared_detail()->innerStatus}.as_status(), Status::BadNodeIdUnknown);
  ASSERT_NE(result.shared_detail()->cause, nullptr);
  EXPECT_EQ(
    ::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::namespaceIndex.value()), "1");
  EXPECT_EQ(::ua::test_utils::error_context(result.shared_detail().get(), ContextKeys::namespaceUri.value()),
    "urn:nmp-missing-parent");

  auto after = enumerate_nodes(*addressSpace, uint16_t{1});
  ASSERT_TRUE(after);
  EXPECT_EQ(after.value().size(), before.value().size());
  addressSpace.reset();
  ::ua::test_utils::drain_with_timeout(pool);
  EXPECT_EQ(callbackCount.load(), 1u);
}

}  // namespace
