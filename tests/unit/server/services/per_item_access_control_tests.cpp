// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Per-service tests that pin the per-item authorization contract: one service
/// request snapshots the session's immutable `AccessIdentity` once and retains
/// that same authorization state across asynchronous node resolution.

#include <gtest/gtest.h>

#include "access_control_test_support.h"
#include "test_utilities.h"

#include "ua_access_level_type.h"
#include "ua_datatype_id.h"
#include "ua_enum_value_type.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_browse_service.h"
#include "ua_diagnostic_policy.h"
#include "ua_error_detail.h"
#include "ua_method_id.h"
#include "ua_method_service_set.h"
#include "ua_namespace_delegates.h"
#include "ua_node_management_service.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_security_policy.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"
#include "ua_translate_browse_paths_service.h"

#include "ua_add_nodes_item.h"
#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_references_item.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_item.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_service_fault.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <future>
#include <memory>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

// ============================================================================
// Test session info
// ============================================================================

class TestSessionInfo final : public SessionInfo, public SessionSecurityContext
{
public:
  explicit TestSessionInfo(boost::asio::any_io_executor executor)
    : mExecutor(executor),
      mAppCfg(std::make_shared<const ApplicationConfig>(ApplicationConfig::load_default())),
      mAddressSpace(AddressSpace::create("urn:test", mExecutor))
  {
    auto security = std::make_shared<EndpointSecurityContext>();
    security->endpointPolicyId = "L/None";
    security->messageSecurityMode = MessageSecurityMode::None;
    security->securityPolicyId = SecurityPolicyId::None;
    mSecurity = std::move(security);

    auto user = std::make_shared<UserIdentity>();
    user->userId = "anonymous";
    user->displayName = "Anonymous";
    user->kind = UserTokenKind::Anonymous;
    mUser = std::move(user);
    mAccessIdentity = ua::test_helpers::configure_test_access(mAddressSpace, mUser, mSecurity);
  }

  boost::asio::any_io_executor executor() const
  {
    return mExecutor;
  }

  AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ApplicationConfig& configuration() const override
  {
    return *mAppCfg;
  }

  const ServerConfig& server_configuration() const override
  {
    return serverCfg;
  }

  DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return ua::server::detail::make_diagnostic_security_context(
      *mSecurity, *mUser, serverCfg.diagnosticPolicy);
  }

  Logger logger() const override
  {
    return {};
  }

  NodeId session_id() const override
  {
    return NodeId{1, 42u};
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mSecurity;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    ++mAccessIdentityReadCount;
    if (mPoisonAccessIdentityAfterFirstRead && mAccessIdentityReadCount > 1)
      return nullptr;
    return mAccessIdentity;
  }

  void poison_access_identity_after_first_read()
  {
    mPoisonAccessIdentityAfterFirstRead = true;
  }

  std::size_t access_identity_read_count() const
  {
    return mAccessIdentityReadCount;
  }

  ServerConfig serverCfg;

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ApplicationConfig> mAppCfg;
  AddressSpace mAddressSpace;
  std::shared_ptr<const EndpointSecurityContext> mSecurity;
  std::shared_ptr<const UserIdentity> mUser;
  std::shared_ptr<const AccessIdentity> mAccessIdentity;
  mutable bool mPoisonAccessIdentityAfterFirstRead = false;
  mutable std::size_t mAccessIdentityReadCount = 0;
};

// ============================================================================
// Pass-through NodeManagement delegate (success for every item)
// ============================================================================

class PassThroughDelegate final : public NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      AddNodesResult r;
      r.status_code() = Status::Good;
      const auto& requested = items[i].item.requested_new_node_id().node_id();
      r.added_node_id() = requested.is_null() ? NodeId{items[i].destination.namespaceIndex,
                                                  static_cast<std::uint32_t>(60000u + i)}
                                              : requested;
      batch.items.emplace_back(std::move(r));
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<AddReferencesItem> items, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(items.size());
    callback(std::move(batch));
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteNodesItem> items, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(items.size());
    callback(std::move(batch));
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(items.size());
    callback(std::move(batch));
  }
};

// ============================================================================
// Common assertion
// ============================================================================

void expect_one_access_identity_snapshot(const TestSessionInfo& session)
{
  EXPECT_EQ(session.access_identity_read_count(), 1u)
    << "one service request must retain one immutable AccessIdentity snapshot";
}

}  // namespace

// ============================================================================
// Browse
// ============================================================================

TEST(PerItemAccessControlTests, BrowseUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  // Browse drives per-item authz only after find_node succeeds; create a local node.
  const NodeId nodeId{1, 9000u};
  (void)si->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});

  BrowseRequest req;
  req.request_header().request_handle() = 1;
  BrowseDescription bd;
  bd.node_id() = nodeId;
  req.nodes_to_browse().payload().push_back(std::move(bd));

  std::promise<BrowseService::BrowseServiceResponse> p;
  auto fut = p.get_future();
  auto svc = BrowseService::create(si, {}, 1, std::move(req), ex, [&](auto r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// TranslateBrowsePaths
// ============================================================================

TEST(PerItemAccessControlTests, TranslateBrowsePathsUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  // TranslateBrowsePaths exercises per-item authz on the starting node after find succeeds.
  const NodeId startNodeId{1, 9100u};
  (void)si->address_space().try_create_node_sync(startNodeId, NodeClass::Object, {});

  TranslateBrowsePathsToNodeIdsRequest req;
  req.request_header().request_handle() = 1;

  BrowsePath bp;
  bp.starting_node() = startNodeId;
  RelativePath rp;
  RelativePathElement el;
  el.reference_type_id() = NodeId{0, ReferenceTypeId::HierarchicalReferences};
  el.is_inverse() = false;
  el.include_subtypes() = true;
  rp.elements().payload().push_back(std::move(el));
  bp.relative_path() = std::move(rp);
  req.browse_paths().payload().push_back(std::move(bp));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = TranslateBrowsePathsService::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Call (MethodServiceSet)
// ============================================================================

TEST(PerItemAccessControlTests, CallUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  // Call drives per-item authz on the method node after find succeeds.
  // Create both the object and method nodes locally so the find_node lookup succeeds.
  const NodeId objectId{1, 9200u};
  const NodeId methodId{1, 9201u};
  (void)si->address_space().try_create_node_sync(objectId, NodeClass::Object, {});
  (void)si->address_space().try_create_sync<MethodAccessor>(methodId, NodeClass::Method);

  CallRequest req;
  req.request_header().request_handle() = 1;
  CallMethodRequest cmr;
  cmr.object_id() = objectId;
  cmr.method_id() = methodId;
  req.methods_to_call().payload().push_back(std::move(cmr));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    MethodServiceSet::create(si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Read (AttributeServiceSet)
// ============================================================================

TEST(PerItemAccessControlTests, ReadUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  // Read drives per-item authz on the resolved node. NodeClass is a non-Value
  // Attribute, so per Part 3 section 8.55 Table 37 it is gated by the Browse permission
  // (Read gates only the Value Attribute) - the authz operation must be Browse.
  const NodeId nodeId{1, 9300u};
  (void)si->address_space().try_create_node_sync(nodeId, NodeClass::Object, {});

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::NodeClass);
  req.nodes_to_read().payload().push_back(std::move(rvid));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = AttributeServiceSet::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// Write (AttributeServiceSet)
// ============================================================================

TEST(PerItemAccessControlTests, WriteUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  // Use a writable variable node so the Write reaches per-item authz.
  const NodeId varId{1, 7001u};
  auto varResult = si->address_space().try_create_sync<VariableAccessor>(varId, NodeClass::Variable);
  ASSERT_TRUE(varResult.is_good());
  AccessLevelType al;
  al.set(AccessLevelType::Bit::CurrentWrite);
  varResult.value().set_access_level(al);

  WriteRequest req;
  req.request_header().request_handle() = 1;
  WriteValue wv;
  wv.node_id() = varId;
  wv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  wv.value().value() = Variant{int32_t{42}};
  req.nodes_to_write().payload().push_back(std::move(wv));

  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc =
    AttributeServiceSet::create(si, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// NodeManagement: AddNodes
// ============================================================================

TEST(PerItemAccessControlTests, AddNodesUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  // Parent node must exist for the find-then-authz pipeline.
  const NodeId parentId{1, 8000u};
  const NodeId objectTypeId{1, 8001u};
  (void)si->address_space().try_create_node_sync(parentId, NodeClass::Object, {});
  (void)si->address_space().try_create_node_sync(objectTypeId, NodeClass::ObjectType, {});

  AddNodesRequest req;
  req.request_header().request_handle() = 1;
  AddNodesItem item;
  item.parent_node_id().node_id() = parentId;
  item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  item.browse_name() = QualifiedName{parentId.namespace_index(), "AuthorizedObject"};
  item.node_class() = NodeClass::Object;
  item.type_definition().node_id() = objectTypeId;
  req.nodes_to_add().payload().push_back(std::move(item));

  auto handler = std::make_shared<PassThroughDelegate>();
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = NodeManagementService::create(
    si, handler, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// NodeManagement: DeleteNodes
// ============================================================================

TEST(PerItemAccessControlTests, DeleteNodesUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  const NodeId targetId{1, 8100u};
  (void)si->address_space().try_create_node_sync(targetId, NodeClass::Object, {});

  DeleteNodesRequest req;
  req.request_header().request_handle() = 1;
  DeleteNodesItem item;
  item.node_id() = targetId;
  req.nodes_to_delete().payload().push_back(std::move(item));

  auto handler = std::make_shared<PassThroughDelegate>();
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = NodeManagementService::create(
    si, handler, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// NodeManagement: AddReferences
// ============================================================================

TEST(PerItemAccessControlTests, AddReferencesUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  const NodeId sourceId{1, 8200u};
  const NodeId targetId{1, 8201u};
  (void)si->address_space().try_create_node_sync(sourceId, NodeClass::Object, {});
  (void)si->address_space().try_create_node_sync(targetId, NodeClass::Object, {});

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;
  AddReferencesItem item;
  item.source_node_id() = sourceId;
  item.reference_type_id() = NodeId{0, ReferenceTypeId::Organizes};
  item.is_forward() = true;
  item.target_node_id().node_id() = targetId;
  item.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(item));

  auto handler = std::make_shared<PassThroughDelegate>();
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = NodeManagementService::create(
    si, handler, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// ============================================================================
// NodeManagement: DeleteReferences
// ============================================================================

TEST(PerItemAccessControlTests, DeleteReferencesUsesSessionContext)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  si->poison_access_identity_after_first_read();

  const NodeId sourceId{1, 8300u};
  const NodeId targetId{1, 8301u};
  const NodeId referenceTypeId{1, 8302u};
  (void)si->address_space().try_create_node_sync(sourceId, NodeClass::Object, {});
  (void)si->address_space().try_create_node_sync(targetId, NodeClass::Object, {});
  (void)si->address_space().try_create_node_sync(referenceTypeId, NodeClass::ReferenceType, {});

  DeleteReferencesRequest req;
  req.request_header().request_handle() = 1;
  DeleteReferencesItem item;
  item.source_node_id() = sourceId;
  item.reference_type_id() = referenceTypeId;
  item.is_forward() = true;
  item.target_node_id().node_id() = targetId;
  req.references_to_delete().payload().push_back(std::move(item));

  auto handler = std::make_shared<PassThroughDelegate>();
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = NodeManagementService::create(
    si, handler, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  (void)fut.get();

  expect_one_access_identity_snapshot(*si);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- SVC-8: the Part-19 projections authorize the owner they disclose (SVR-AUTHZ-011) --------------

namespace
{
struct ProjectionModel
{
  NodeId ownerId{1, 9600u};
  NodeId enumValuesId{1, 9601u};
  NodeId valueAsTextId{1, 9602u};
  NodeId dictionaryEntriesId{1, 9603u};
};

// A MultiStateValueDiscrete-shaped owner (Value 2 -> "High") with a ValueAsText Property and a bare
// ValueAsDictionaryEntries Property, both pointing back at the owner through inverse HasProperty.
ProjectionModel build_projection_model(AddressSpace addressSpace)
{
  ProjectionModel m;
  auto ownerNode = addressSpace.create_node_sync(m.ownerId, NodeClass::Variable);
  auto owner = ownerNode.as<VariableAccessor>();
  EXPECT_TRUE(owner.has_value());
  owner->set_browse_name(QualifiedName{1, "State"});
  owner->set_data_type(NodeId{DataTypeId::Int64});
  owner->write_value_sync(Variant{int64_t{2}});
  auto enumNode = addressSpace.create_node_sync(m.enumValuesId, NodeClass::Variable);
  auto enumValues = enumNode.as<VariableAccessor>();
  EXPECT_TRUE(enumValues.has_value());
  enumValues->set_browse_name(QualifiedName{0, "EnumValues"});
  enumValues->set_data_type(NodeId{DataTypeId::EnumValueType});
  Array<RefStructure<Structure>> entries;
  for (const auto& [value, label] : std::vector<std::pair<int64_t, std::string>>{{1, "Low"}, {2, "High"}})
  {
    auto entry = std::make_unique<EnumValueType>();
    entry->value() = value;
    entry->display_name() = LocalizedText{"", label};
    entries.push_back(RefStructure<Structure>{std::move(entry)});
  }
  enumValues->write_value_sync(Variant{std::move(entries)});
  ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, m.enumValuesId);
  for (const auto& [id, name] : std::vector<std::pair<NodeId, const char*>>{
         {m.valueAsTextId, "ValueAsText"}, {m.dictionaryEntriesId, "ValueAsDictionaryEntries"}})
  {
    auto node = addressSpace.create_node_sync(id, NodeClass::Variable);
    auto property = node.as<VariableAccessor>();
    EXPECT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, name});
    property->set_data_type(NodeId{DataTypeId::LocalizedText});
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, id);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, m.ownerId, false);
  }
  return m;
}

DataValue read_value(
  std::shared_ptr<TestSessionInfo> si, boost::asio::any_io_executor ex, const NodeId& nodeId)
{
  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = nodeId;
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  req.nodes_to_read().payload().push_back(std::move(rvid));
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = AttributeServiceSet::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  auto response = fut.get();
  auto* read = dynamic_cast<ReadResponse*>(response.second.get());
  if (!read || read->results().size() != 1)
  {
    ADD_FAILURE() << "no single Read result";
    return {};
  }
  return read->results()[0];
}

StatusCode status_of(const DataValue& value)
{
  return value.status() ? *value.status() : StatusCode{Status::Good};
}
}  // namespace

// @verifies AC-SVR-AUTHZ-011-VALUEASTEXT-AUTHORIZES-THE-OWNER-IT-DISCLOSES
TEST(PerItemAccessControlTests, ValueAsTextOfAReadDeniedOwnerIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  const auto m = build_projection_model(si->address_space());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::Read);
  auto ownerNode = si->address_space().find_node_sync(m.ownerId);
  ua::test_helpers::set_test_node_permissions(ownerNode, permissions);

  const auto value = read_value(si, ex, m.valueAsTextId);
  EXPECT_EQ(status_of(value).as_status(), Status::BadUserAccessDenied)
    << "the owner's Value is what is disclosed";
  EXPECT_TRUE(value.value().empty());
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-SVR-AUTHZ-011-VALUEASTEXT-AUTHORIZES-THE-OWNER-IT-DISCLOSES
TEST(PerItemAccessControlTests, ValueAsTextOfANonCurrentReadOwnerIsNotReadable)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  const auto m = build_projection_model(si->address_space());
  auto owner = si->address_space().find_node_sync(m.ownerId).as<VariableAccessor>();
  ASSERT_TRUE(owner.has_value());
  owner->set_access_level(AccessLevelType{});

  const auto value = read_value(si, ex, m.valueAsTextId);
  EXPECT_EQ(status_of(value).as_status(), Status::BadNotReadable);
  EXPECT_TRUE(value.value().empty());
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-SVR-AUTHZ-011-VALUEASTEXT-AUTHORIZES-THE-OWNER-IT-DISCLOSES
// The control: a readable, permitted owner is projected as before.
TEST(PerItemAccessControlTests, ValueAsTextOfAReadableOwnerIsProjected)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  const auto m = build_projection_model(si->address_space());

  const auto value = read_value(si, ex, m.valueAsTextId);
  EXPECT_TRUE(status_of(value).is_good());
  EXPECT_FALSE(value.value().empty()) << "the owner's current value has a text form";
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-SVR-AUTHZ-011-VALUEASTEXT-AUTHORIZES-THE-OWNER-IT-DISCLOSES
// The dictionary projection is gated by the same owner rule, before it looks for its tables.
TEST(PerItemAccessControlTests, ValueAsDictionaryEntriesOfAReadDeniedOwnerIsRefused)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  const auto m = build_projection_model(si->address_space());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::Read);
  auto ownerNode = si->address_space().find_node_sync(m.ownerId);
  ua::test_helpers::set_test_node_permissions(ownerNode, permissions);

  const auto value = read_value(si, ex, m.dictionaryEntriesId);
  EXPECT_EQ(status_of(value).as_status(), Status::BadUserAccessDenied);
  // The control: with the owner readable the (table-less) projection is not a permission failure.
  ua::test_helpers::set_test_node_permissions(ownerNode, ua::test_helpers::all_permissions());
  const auto control = read_value(si, ex, m.dictionaryEntriesId);
  EXPECT_NE(status_of(control).as_status(), Status::BadUserAccessDenied);
  ::ua::test_utils::drain_with_timeout(tp);
}

// COMP-ADDRSP-ACCESSOR-ROUTE-05 item 1: the IndexRange of a Read of a Value the Read service projects is
// applied once, to the projected value. ValueAsDictionaryEntries answers the current row of its owner's
// EnumDictionaryEntries, so a range of it narrows that row, whatever the Property itself stores (here,
// nothing).
// @relation(AC-COMP-ADDRSP-ACCESSOR-ROUTE-05-A-RANGED-READ-OF-A-PROJECTED-VALUE-IS-NARROWED-ONCE, scope=function)
TEST(NodeAccessorRoute, ARangedReadOfAProjectedValueIsNarrowedOnce)
{
  boost::asio::thread_pool tp;
  auto ex = tp.get_executor();
  auto si = std::make_shared<TestSessionInfo>(ex);
  auto addressSpace = si->address_space();
  const NodeId ownerId{1, 9610u};
  const NodeId enumValuesId{1, 9611u};
  const NodeId enumDictionaryEntriesId{1, 9612u};
  const NodeId dictionaryEntriesId{1, 9613u};
  const NodeId e1{1, 9623u};
  const NodeId e2{1, 9624u};
  const NodeId e3{1, 9625u};

  // O: a MultiStateDictionaryEntryDiscrete Variable whose current Value 2 selects the row [E1, E2, E3].
  auto ownerNode = addressSpace.create_node_sync(ownerId, NodeClass::Variable);
  auto owner = ownerNode.as<VariableAccessor>();
  ASSERT_TRUE(owner.has_value());
  owner->set_browse_name(QualifiedName{1, "State"});
  owner->set_data_type(NodeId{DataTypeId::Int64});
  owner->write_value_sync(Variant{int64_t{2}});
  ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition},
    NodeId{VariableTypeId::MultiStateDictionaryEntryDiscreteType});

  const auto addProperty = [&](const NodeId& id, std::string_view name, const NodeId& dataType)
  {
    auto node = addressSpace.create_node_sync(id, NodeClass::Variable);
    auto property = node.as<VariableAccessor>();
    EXPECT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, std::string{name}});
    property->set_data_type(dataType);
    ownerNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, id);
    node.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ownerId, false);
    return property;
  };

  Array<RefStructure<Structure>> entries;
  for (const auto& [value, label] : std::vector<std::pair<int64_t, std::string>>{{1, "Low"}, {2, "High"}})
  {
    auto entry = std::make_unique<EnumValueType>();
    entry->value() = value;
    entry->display_name() = LocalizedText{"", label};
    entries.push_back(RefStructure<Structure>{std::move(entry)});
  }
  auto enumValues = addProperty(enumValuesId, "EnumValues", NodeId{DataTypeId::EnumValueType});
  ASSERT_TRUE(enumValues.has_value());
  enumValues->write_value_sync(Variant{std::move(entries)});
  auto enumDictionaryEntries =
    addProperty(enumDictionaryEntriesId, "EnumDictionaryEntries", NodeId{DataTypeId::NodeId});
  ASSERT_TRUE(enumDictionaryEntries.has_value());
  enumDictionaryEntries->write_value_sync(Variant{
    Array<NodeId>{Dimensions{2, 3}, {NodeId{1, 9620u}, NodeId{1, 9621u}, NodeId{1, 9622u}, e1, e2, e3}}});
  // P: its stored Value is left null.
  ASSERT_TRUE(
    addProperty(dictionaryEntriesId, "ValueAsDictionaryEntries", NodeId{DataTypeId::NodeId}).has_value());

  ReadRequest req;
  req.request_header().request_handle() = 1;
  ReadValueId rvid;
  rvid.node_id() = dictionaryEntriesId;
  rvid.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
  rvid.index_range() = "1";
  req.nodes_to_read().payload().push_back(std::move(rvid));
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = AttributeServiceSet::create(
    si, {}, 1, std::move(req), ex, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;
  auto response = fut.get();
  auto* read = dynamic_cast<ReadResponse*>(response.second.get());
  ASSERT_NE(read, nullptr) << "the Read answered a fault";
  ASSERT_EQ(read->results().size(), 1u);
  const auto& value = read->results()[0];

  EXPECT_EQ(status_of(value).as_status(), Status::Good)
    << "the Read answered 0x" << std::hex << status_of(value).as_uint32();
  ASSERT_TRUE(value.value().is_array()) << "the Read answered no array";
  const auto& range = value.value().as<Array<NodeId>>();
  ASSERT_EQ(static_cast<std::size_t>(range.size()), 1u) << "the Read did not answer exactly the range 1";
  EXPECT_EQ(range[0], e2);

  si.reset();
  ::ua::test_utils::drain_with_timeout(tp);
}
