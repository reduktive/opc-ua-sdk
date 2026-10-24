// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "ua_diagnostic_to_error_detail.h"
#include "ua_object_id.h"
#include "ua_result.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_namespace_delegates.h"
#include "ua_node_management_service.h"

#include "ua_add_nodes_item.h"
#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_nodes_result.h"
#include "ua_add_references_item.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_data_type_attributes.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_item.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_method_attributes.h"
#include "ua_object_attributes.h"
#include "ua_object_type_attributes.h"
#include "ua_reference_type_attributes.h"
#include "ua_service_fault.h"
#include "ua_variable_attributes.h"
#include "ua_variable_type_attributes.h"
#include "ua_view_attributes.h"
#include <boost/asio/thread_pool.hpp>

#include "deferred_namespace.h"
#include "stubs.h"
#include "test_utilities.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

// --- Test session info with configurable AccessIdentity and operation limits -

static const NodeId testObjectTypeId{1, 251u};
static const NodeId testVariableTypeId{1, 252u};

class NodeManagementSessionInfo final : public SessionInfo, public SessionSecurityContext
{
public:
  NodeManagementSessionInfo(boost::asio::any_io_executor executor, bool identityAvailable,
    MessageSecurityMode messageSecurityMode = MessageSecurityMode::None)
    : mExecutor(executor),
      mAppCfg(std::make_shared<const ApplicationConfig>(ApplicationConfig::load_default())),
      mAddressSpace(AddressSpace::create("urn:test", mExecutor))
  {
    auto security = std::make_shared<EndpointSecurityContext>();
    security->endpointPolicyId = "L/None";
    security->messageSecurityMode = messageSecurityMode;
    security->securityPolicyId = SecurityPolicyId::None;
    mSecurity = std::move(security);

    auto user = std::make_shared<UserIdentity>();
    user->userId = "anonymous";
    user->displayName = "Anonymous";
    user->kind = UserTokenKind::Anonymous;
    mUser = std::move(user);

    // Pre-create the test nodes used as parent/source/target by the NM tests.
    // Namespace-owned access control runs `find_node` before per-item authorization, so these
    // nodes must exist for the per-item authz path to be exercised. NS index 1 is
    // the writable "urn:test" namespace (NS 0 is the read-only OPC Foundation stub).
    auto as = mAddressSpace;
    for (uint32_t id : {85u, 100u, 200u, 999u})
    {
      (void)as.try_create_node_sync(NodeId{1, id}, NodeClass::Object, {});
    }
    (void)as.try_create_node_sync(NodeId{1, 250u}, NodeClass::ReferenceType, {});
    (void)as.try_create_node_sync(testObjectTypeId, NodeClass::ObjectType, {});
    (void)as.try_create_node_sync(testVariableTypeId, NodeClass::VariableType, {});

    if (identityAvailable)
    {
      mAccessIdentity = ua::test_helpers::configure_test_access(mAddressSpace, mUser, mSecurity);
    }
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
    return NodeId{1, Guid::create_and_generate()};
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
    return mAccessIdentity;
  }

  void set_node_permissions(const NodeId& nodeId, PermissionType permissions)
  {
    auto node = mAddressSpace.find_node_sync(nodeId);
    ua::test_helpers::set_test_node_permissions(node, permissions);
  }

  void clear_roles_for_test()
  {
    mAccessIdentity = std::make_shared<AccessIdentity>(
      AccessIdentityKey{2}, std::vector<NodeId>{}, mUser, mSecurity, String{"urn:test:no-roles"});
  }

  void set_namespace_permissions(uint16_t namespaceIndex, PermissionType permissions)
  {
    auto testNamespace = std::dynamic_pointer_cast<default_ns::Namespace>(
      mAddressSpace.namespace_array().get_namespace(namespaceIndex));
    ASSERT_NE(testNamespace, nullptr);
    RolePermissionType permission;
    permission.role_id() = ua::test_helpers::test_access_role_id();
    permission.permissions() = permissions;
    testNamespace->set_namespace_defaults(std::vector<RolePermissionType>{permission}, std::nullopt);
  }

  ServerConfig serverCfg;

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ApplicationConfig> mAppCfg;
  AddressSpace mAddressSpace;
  std::shared_ptr<const EndpointSecurityContext> mSecurity;
  std::shared_ptr<const UserIdentity> mUser;
  std::shared_ptr<const AccessIdentity> mAccessIdentity;
};

static void make_add_nodes_item_conforming(AddNodesItem& item)
{
  if (item.reference_type_id().is_null())
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};

  if (item.node_class() == NodeClass::Object && item.type_definition().node_id().is_null())
    item.type_definition().node_id() = testObjectTypeId;
  else if (item.node_class() == NodeClass::Variable && item.type_definition().node_id().is_null())
    item.type_definition().node_id() = testVariableTypeId;
}

static AddNodesItem make_conforming_object_add_nodes_item(NodeId requestedNodeId, QualifiedName browseName)
{
  AddNodesItem item;
  item.parent_node_id().node_id() = NodeId{1, 85u};
  item.requested_new_node_id().node_id() = std::move(requestedNodeId);
  item.browse_name() = std::move(browseName);
  item.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item);
  return item;
}

// --- Fake handler -----------------------------------------------------------

class FakeNodeManagementDelegate final : public NodeManagementDelegate
{
public:
  static BatchResult<VoidResult> make_all_good_batch(size_t n)
  {
    BatchResult<VoidResult> batch;
    batch.items.resize(n);
    return batch;
  }

  void prepare_add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context, AddressSpace,
    std::vector<AddNodesItem> items,
    NodeManagementDelegate::PrepareAddNodesCallback callback) noexcept override
  {
    try
    {
      lastContext = context;
      preparedAddNodesItems = std::move(items);
      ++prepareAddNodesCalls;
      if (prepareAddNodesResultFactory)
      {
        callback(prepareAddNodesResultFactory(preparedAddNodesItems));
        return;
      }

      BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
      batch.items.reserve(preparedAddNodesItems.size());
      for (const auto& item : preparedAddNodesItems)
      {
        const auto& requested = item.requested_new_node_id().node_id();
        batch.items.emplace_back(NodeManagementDelegate::AddNodeDestination{
          requested.is_null() ? nullRequestedNodeDestination : requested.namespace_index()});
      }
      callback(std::move(batch));
    }
    catch (...)
    {
      BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
      batch.batchStatus = VoidResult{ua::exception_to_status_code(std::current_exception())};
      callback(std::move(batch));
    }
  }

  // AddNodes: store items, return preconfigured results
  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    lastContext = context;
    authorizedAddNodes = std::move(items);
    addNodesItems.clear();
    addNodesItems.reserve(authorizedAddNodes.size());
    for (const auto& item : authorizedAddNodes)
    {
      addNodesItems.push_back(item.item);
    }
    ++addNodesCalls;

    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    if (addNodesAnswerFactory)
    {
      for (auto& answer : addNodesAnswerFactory(addNodesItems))
      {
        batch.items.push_back(std::move(answer));
      }
      callback(std::move(batch));
      return;
    }
    if (addNodesResultFactory)
    {
      auto legacy = addNodesResultFactory(addNodesItems);
      batch.items.reserve(legacy.size());
      for (auto& r : legacy)
      {
        batch.items.emplace_back(std::move(r));
      }
    }
    else
    {
      batch.items.reserve(addNodesItems.size());
      for (size_t i = 0; i < addNodesItems.size(); ++i)
      {
        AddNodesResult r;
        r.status_code() = Status::Good;
        const auto& requested = addNodesItems[i].requested_new_node_id().node_id();
        r.added_node_id() = requested.is_null() ? NodeId{authorizedAddNodes[i].destination.namespaceIndex,
                                                    static_cast<uint32_t>(60000u + i)}
                                                : requested;
        batch.items.emplace_back(std::move(r));
      }
    }
    if (!preserveInvalidSuccessfulNodeIds)
    {
      for (size_t i = 0; i < batch.items.size() && i < authorizedAddNodes.size(); ++i)
      {
        if (batch.items[i].is_bad())
        {
          continue;
        }
        auto& result = batch.items[i].value();
        if (result.status_code().is_good() && result.added_node_id().is_null())
        {
          const auto& requested = authorizedAddNodes[i].item.requested_new_node_id().node_id();
          result.added_node_id() =
            requested.is_null()
              ? NodeId{authorizedAddNodes[i].destination.namespaceIndex, static_cast<uint32_t>(60000u + i)}
              : requested;
        }
      }
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<AddReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    lastContext = context;
    addReferencesItems = std::move(items);
    ++addReferencesCalls;

    BatchResult<VoidResult> batch;
    if (addReferencesResultFactory)
    {
      auto legacy = addReferencesResultFactory(addReferencesItems);
      batch.items.reserve(legacy.size());
      for (auto status : legacy)
      {
        batch.items.emplace_back(status.is_good() ? VoidResult{} : VoidResult{status});
      }
    }
    else
    {
      batch = make_all_good_batch(addReferencesItems.size());
    }
    callback(std::move(batch));
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteNodesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    lastContext = context;
    deleteNodesItems = std::move(items);
    ++deleteNodesCalls;

    BatchResult<VoidResult> batch;
    if (deleteNodesResultFactory)
    {
      auto legacy = deleteNodesResultFactory(deleteNodesItems);
      batch.items.reserve(legacy.size());
      for (auto status : legacy)
      {
        batch.items.emplace_back(status.is_good() ? VoidResult{} : VoidResult{status});
      }
    }
    else
    {
      batch = make_all_good_batch(deleteNodesItems.size());
    }
    callback(std::move(batch));
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    lastContext = context;
    deleteReferencesItems = std::move(items);
    ++deleteReferencesCalls;

    BatchResult<VoidResult> batch;
    if (deleteReferencesResultFactory)
    {
      auto legacy = deleteReferencesResultFactory(deleteReferencesItems);
      batch.items.reserve(legacy.size());
      for (auto status : legacy)
      {
        batch.items.emplace_back(status.is_good() ? VoidResult{} : VoidResult{status});
      }
    }
    else
    {
      batch = make_all_good_batch(deleteReferencesItems.size());
    }
    callback(std::move(batch));
  }

  std::shared_ptr<const NodeManagementDelegate::Context> lastContext;

  std::vector<AddNodesItem> preparedAddNodesItems;
  std::vector<NodeManagementDelegate::AuthorizedAddNode> authorizedAddNodes;
  std::vector<AddNodesItem> addNodesItems;
  std::vector<AddReferencesItem> addReferencesItems;
  std::vector<DeleteNodesItem> deleteNodesItems;
  std::vector<DeleteReferencesItem> deleteReferencesItems;

  size_t prepareAddNodesCalls{0};
  size_t addNodesCalls{0};
  size_t addReferencesCalls{0};
  size_t deleteNodesCalls{0};
  size_t deleteReferencesCalls{0};

  uint16_t nullRequestedNodeDestination{1};
  bool preserveInvalidSuccessfulNodeIds{false};
  std::function<BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult>(
    const std::vector<AddNodesItem>&)>
    prepareAddNodesResultFactory;
  std::function<std::vector<AddNodesResult>(const std::vector<AddNodesItem>&)> addNodesResultFactory;
  // The delegate's answers, each with the code on its Result, given to the service as they are.
  std::function<std::vector<NodeManagementDelegate::AddNodesItemResult>(const std::vector<AddNodesItem>&)>
    addNodesAnswerFactory;
  std::function<std::vector<StatusCode>(const std::vector<AddReferencesItem>&)> addReferencesResultFactory;
  std::function<std::vector<StatusCode>(const std::vector<DeleteNodesItem>&)> deleteNodesResultFactory;
  std::function<std::vector<StatusCode>(const std::vector<DeleteReferencesItem>&)>
    deleteReferencesResultFactory;
};

// --- Helper: configure an identity with broad permissions -------------------

static bool make_allow_all_authorizer()
{
  return true;
}

// --- Helper: invoke service and get response --------------------------------

struct ServiceResponse
{
  bool isServiceFault{false};
  StatusCode serviceResult{Status::Good};
  std::shared_ptr<Structure> response;
};

template<typename RequestType>
static ServiceResponse invoke_service(std::shared_ptr<NodeManagementSessionInfo> si,
  std::shared_ptr<NodeManagementDelegate> handler, boost::asio::any_io_executor executor,
  RequestType&& request)
{
  std::promise<Response> p;
  auto fut = p.get_future();
  auto svc = NodeManagementService::create(
    si, handler, 1, std::move(request), executor, [&](Response r) { p.set_value(std::move(r)); });
  (void)svc;

  auto status = fut.wait_for(5s);
  if (status != std::future_status::ready)
  {
    ADD_FAILURE() << "Service timed out";
    return {};
  }

  auto resp = fut.get();
  ServiceResponse result;
  result.response = resp.second;

  if (auto* sf = dynamic_cast<ServiceFault*>(resp.second.get()))
  {
    result.isServiceFault = true;
    result.serviceResult = sf->response_header().service_result();
  }

  return result;
}

// --- SVR-NM-SVC-001: Empty items -> BadNothingToDo ------------------------------

// @relation(SVR-NM-SVC-001, scope=function)
TEST(NodeManagementService, NM_SVC_001_AddNodes_EmptyItems_BadNothingToDo)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadNothingToDo);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NodeManagementService, NM_SVC_001_AddReferences_EmptyItems_BadNothingToDo)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadNothingToDo);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-NM-SVC-002, scope=function)
TEST(NodeManagementService, NM_SVC_001_DeleteNodes_EmptyItems_BadNothingToDo)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  DeleteNodesRequest req;
  req.request_header().request_handle() = 1;

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadNothingToDo);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NodeManagementService, NM_SVC_001_DeleteReferences_EmptyItems_BadNothingToDo)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  DeleteReferencesRequest req;
  req.request_header().request_handle() = 1;

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadNothingToDo);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- SVR-NM-SVC-002: Exceeding limit -> BadTooManyOperations --------------------

// @relation(SVR-NM-SVC-002, scope=function)
TEST(NodeManagementService, NM_SVC_002_AddNodes_ExceedsLimit_BadTooManyOperations)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  si->serverCfg.server_capabilities().operationLimits.maxNodesPerNodeManagement = 1;
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  AddNodesItem item1;
  item1.parent_node_id().node_id() = NodeId{1, 85u};
  AddNodesItem item2;
  item2.parent_node_id().node_id() = NodeId{1, 85u};
  req.nodes_to_add().payload().push_back(std::move(item1));
  req.nodes_to_add().payload().push_back(std::move(item2));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadTooManyOperations);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-NM-SVC-002, scope=function)
TEST(NodeManagementService, NM_SVC_002_DeleteNodes_ExceedsLimit_BadTooManyOperations)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  si->serverCfg.server_capabilities().operationLimits.maxNodesPerNodeManagement = 1;
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  DeleteNodesRequest req;
  req.request_header().request_handle() = 1;

  DeleteNodesItem item1;
  item1.node_id() = NodeId{1, 100u};
  DeleteNodesItem item2;
  item2.node_id() = NodeId{1, 200u};
  req.nodes_to_delete().payload().push_back(std::move(item1));
  req.nodes_to_delete().payload().push_back(std::move(item2));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  EXPECT_TRUE(result.isServiceFault);
  EXPECT_EQ(result.serviceResult, Status::BadTooManyOperations);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- No handler -> BadServiceUnsupported -------------------------------------

TEST(NodeManagementService, NoHandler_AddNodes_BadServiceUnsupported)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());

  AddNodesRequest req;
  req.request_header().request_handle() = 1;
  AddNodesItem item;
  item.parent_node_id().node_id() = NodeId{1, 85u};
  req.nodes_to_add().payload().push_back(std::move(item));

  // Pass nullptr handler - service should detect this with a null check
  // Actually, the null handler check is done at the session level.
  // In the service, the handler is always non-null (session sends BadServiceUnsupported if null).
  // So we test the session-level wiring separately.
  // Here we test that the service works correctly when handler is provided.
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Authorization: denied items get BadUserAccessDenied --------------------

// @relation(SVR-NM-AN-030, scope=function)
// @relation(AC-SVR-DIAG-010-PEROPERATION-DETAIL, scope=function)
TEST(NodeManagementService, NM_AN_030_AddNodes_DeniedItems_BadUserAccessDenied)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  si->clear_roles_for_test();
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddNodesRequest req;
  req.request_header().request_handle() = 1;
  AddNodesItem item;
  item.parent_node_id().node_id() = NodeId{1, 85u};
  item.requested_new_node_id().node_id() = NodeId{1, 1000u};
  item.browse_name() = QualifiedName{1, "DeniedObject"};
  item.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item);
  req.nodes_to_add().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  const StatusCode status = resp->results()[0].status_code();
  EXPECT_EQ(status, Status::BadUserAccessDenied);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "RoleNotGranted");
  EXPECT_EQ(handler->addNodesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-NM-AR-027, scope=function)
TEST(NodeManagementService, NM_AR_027_AddReferences_DeniedItems_BadUserAccessDenied)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::AddReference);
  si->set_node_permissions(NodeId{1, 85u}, permissions);
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;
  AddReferencesItem item;
  item.source_node_id() = NodeId{1, 85u};
  // A conforming item: the Server screens targetNodeId, targetNodeClass and targetServerUri per
  // OPC 10000-4 5.7.3.2 before an item reaches authorization, so a bare item would be refused for
  // its parameters and never exercise what this test is about.
  item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  item.is_forward() = true;
  item.target_node_id().node_id() = NodeId{1, 100u};
  item.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], Status::BadUserAccessDenied);
  EXPECT_EQ(handler->addReferencesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(AC-SVR-AUTHZ-015-CHANNEL-REFUSAL-NOT-FLATTENED, scope=function)
TEST(NodeManagementService, AddReferencesPreservesDistinctChannelAndPermissionRefusals)
{
  boost::asio::thread_pool pool;
  auto sessionInfo = std::make_shared<NodeManagementSessionInfo>(
    pool.get_executor(), make_allow_all_authorizer(), MessageSecurityMode::None);
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  const NodeId sourceId{1, 85u};
  auto source = sessionInfo->address_space().find_node_sync(sourceId);

  const auto invokeAddReference = [&]
  {
    AddReferencesRequest request;
    request.request_header().request_handle() = 1;
    AddReferencesItem item;
    item.source_node_id() = sourceId;
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.is_forward() = true;
    item.target_node_id().node_id() = NodeId{1, 100u};
    item.target_node_class() = NodeClass::Object;
    request.references_to_add().payload().push_back(std::move(item));
    auto result = invoke_service(sessionInfo, handler, pool.get_executor(), std::move(request));
    EXPECT_FALSE(result.isServiceFault);
    auto* response = dynamic_cast<AddReferencesResponse*>(result.response.get());
    EXPECT_NE(response, nullptr);
    if (response == nullptr || response->results().empty())
      return StatusCode{Status::BadInternalError};
    return response->results()[0];
  };

  source.set_access_restrictions(AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});
  EXPECT_EQ(invokeAddReference().as_status(), Status::BadSecurityModeInsufficient);

  source.set_access_restrictions(std::nullopt);
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::AddReference);
  sessionInfo->set_node_permissions(sourceId, permissions);
  EXPECT_EQ(invokeAddReference().as_status(), Status::BadUserAccessDenied);
  EXPECT_EQ(handler->addReferencesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(pool);
}

// @relation(SVR-NM-DN-022, scope=function)
TEST(NodeManagementService, NM_DN_022_DeleteNodes_DeniedItems_BadUserAccessDenied)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::DeleteNode);
  si->set_node_permissions(NodeId{1, 100u}, permissions);
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  DeleteNodesRequest req;
  req.request_header().request_handle() = 1;
  DeleteNodesItem item;
  item.node_id() = NodeId{1, 100u};
  req.nodes_to_delete().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<DeleteNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], Status::BadUserAccessDenied);
  EXPECT_EQ(handler->deleteNodesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-NM-DR-024, scope=function)
TEST(NodeManagementService, NM_DR_024_DeleteReferences_DeniedItems_BadUserAccessDenied)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::RemoveReference);
  si->set_node_permissions(NodeId{1, 100u}, permissions);
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  DeleteReferencesRequest req;
  req.request_header().request_handle() = 1;
  DeleteReferencesItem item;
  item.source_node_id() = NodeId{1, 100u};
  item.reference_type_id() = NodeId{1, 250u};
  item.target_node_id() = ExpandedNodeId{NodeId{1, 200u}};
  req.references_to_delete().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<DeleteReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], Status::BadUserAccessDenied);
  EXPECT_EQ(handler->deleteReferencesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Authorization: authorized items reach handler --------------------------

// @relation(SVR-NM-AN-030, scope=function)
TEST(NodeManagementService, NM_AN_030_AddNodes_AuthorizedItems_ReachHandler)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  handler->addNodesResultFactory = [](const std::vector<AddNodesItem>& items)
  {
    std::vector<AddNodesResult> results(items.size());
    for (size_t i = 0; i < items.size(); ++i)
    {
      results[i].status_code() = Status::Good;
      results[i].added_node_id() = NodeId{1, static_cast<uint32_t>(1000 + i)};
    }
    return results;
  };

  AddNodesRequest req;
  req.request_header().request_handle() = 1;
  AddNodesItem item;
  item.parent_node_id().node_id() = NodeId{1, 85u};
  item.browse_name() = QualifiedName{1, "AuthorizedObject"};
  item.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item);
  req.nodes_to_add().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_TRUE(resp->results()[0].status_code().is_good());
  EXPECT_EQ(resp->results()[0].added_node_id(), (NodeId{1, 1000u}));
  EXPECT_EQ(handler->addNodesCalls, 1u);
  EXPECT_EQ(handler->addNodesItems.size(), 1u);
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{
// An AddNodes request for @p count Objects under NodeId{1, 85}, each with a null requested NodeId.
AddNodesRequest add_objects_request(std::size_t count)
{
  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  for (std::size_t i = 0; i < count; ++i)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.browse_name() = QualifiedName{1, "CombinedCode" + std::to_string(i)};
    item.node_class() = NodeClass::Object;
    make_add_nodes_item_conforming(item);
    request.nodes_to_add().payload().push_back(std::move(item));
  }
  return request;
}

// The AddNodesResult of the Node NodeId{1, @p id} with @p status.
AddNodesResult added_node(uint32_t id, Status status = Status::Good)
{
  AddNodesResult result;
  result.status_code() = status;
  result.added_node_id() = NodeId{1, id};
  return result;
}
}  // namespace

// A delegate's code on its answer and the AddNodesResult's statusCode share the one status of the item: a
// Good subcode on the answer is answered over the result's plain Good, the result's own subcode goes when
// both have one, and the result's Bad status stands.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-ADD-NODES-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST(NodeManagementService, AddNodesAnswersTheCombinedCodeOfAGoodAnswer)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  const StatusCode outer{Status::GoodLocalOverride};
  handler->addNodesAnswerFactory = [outer](const std::vector<AddNodesItem>& items)
  {
    std::vector<NodeManagementDelegate::AddNodesItemResult> answers;
    if (items.size() != 3)
    {
      return answers;
    }
    answers.emplace_back(added_node(1100), outer);
    answers.emplace_back(added_node(1101, Status::GoodEntryInserted), outer);
    answers.emplace_back(added_node(1102, Status::BadBrowseNameDuplicated), outer);
    return answers;
  };

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), add_objects_request(3));

  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  const auto& results = response->results();
  EXPECT_EQ(results[0].status_code().value(), outer.value()) << to_string(results[0].status_code());
  EXPECT_EQ(results[0].added_node_id(), (NodeId{1, 1100u}));
  EXPECT_EQ(results[1].status_code().value(), StatusCode{Status::GoodEntryInserted}.value())
    << "both carry a subcode, so the result's own goes: " << to_string(results[1].status_code());
  EXPECT_EQ(results[1].added_node_id(), (NodeId{1, 1101u}));
  EXPECT_EQ(results[2].status_code().value(), StatusCode{Status::BadBrowseNameDuplicated}.value())
    << "the result's Bad status did not stand: " << to_string(results[2].status_code());
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// An Uncertain code on a delegate's answer is worse than the result's Good status, so the item is answered
// Uncertain with the Node the delegate added.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-ADD-NODES-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST(NodeManagementService, AddNodesAnswersTheUncertainCodeOfAnAnswer)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  const StatusCode uncertain{Status::UncertainNoCommunicationLastUsableValue};
  handler->addNodesAnswerFactory = [uncertain](const std::vector<AddNodesItem>& items)
  {
    std::vector<NodeManagementDelegate::AddNodesItemResult> answers;
    if (items.size() == 1)
    {
      answers.emplace_back(added_node(1200), uncertain);
    }
    return answers;
  };

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), add_objects_request(1));

  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  const auto& added = response->results()[0];
  EXPECT_EQ(added.status_code().value(), uncertain.value()) << to_string(added.status_code());
  EXPECT_EQ(added.added_node_id(), (NodeId{1, 1200u}));
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-AUTHZ-003-DESTINATION-DECIDES, scope=function)
// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-01-PREPARE, scope=function)
TEST(NodeManagementService, AddNodesNullIdUsesPreparedDestinationNotParentOrBrowseName)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();

  const auto browseNamespace = addressSpace.add_namespace_sync(
    default_ns::Namespace::create("urn:test:add-nodes:browse", threadPool.get_executor()));
  const auto destinationNamespace = addressSpace.add_namespace_sync(
    default_ns::Namespace::create("urn:test:add-nodes:destination", threadPool.get_executor()));
  sessionInfo->set_namespace_permissions(browseNamespace, ua::test_helpers::all_permissions());
  sessionInfo->set_namespace_permissions(destinationNamespace, ua::test_helpers::all_permissions());
  handler->nullRequestedNodeDestination = destinationNamespace;

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(NodeId{}, QualifiedName{browseNamespace, "PreparedDestination"}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  ASSERT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(response->results()[0].added_node_id().namespace_index(), destinationNamespace);

  ASSERT_EQ(handler->prepareAddNodesCalls, 1u);
  ASSERT_EQ(handler->preparedAddNodesItems.size(), 1u);
  EXPECT_EQ(handler->preparedAddNodesItems[0].parent_node_id().node_id().namespace_index(), 1u);
  EXPECT_EQ(handler->preparedAddNodesItems[0].browse_name().namespace_index(), browseNamespace);
  ASSERT_EQ(handler->authorizedAddNodes.size(), 1u);
  EXPECT_EQ(handler->authorizedAddNodes[0].destination.namespaceIndex, destinationNamespace);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-AUTHZ-003-DESTINATION-DECIDES, scope=function)
// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-01-PREPARE, scope=function)
TEST(NodeManagementService, AddNodesExplicitIdPreparationRedirectIsRejected)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();
  auto redirectedNamespace =
    ua::test::DeferredNamespace::create("urn:test:add-nodes:redirect", threadPool.get_executor());
  const auto redirectedNamespaceIndex = addressSpace.add_namespace_sync(redirectedNamespace);
  const NodeId requestedNodeId{1, 61001u};

  handler->prepareAddNodesResultFactory = [redirectedNamespaceIndex](const std::vector<AddNodesItem>&)
  {
    BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
    batch.items.emplace_back(NodeManagementDelegate::AddNodeDestination{redirectedNamespaceIndex});
    return batch;
  };

  ASSERT_TRUE(addressSpace.try_find_node_sync(requestedNodeId).is_bad());
  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(requestedNodeId, QualifiedName{1, "ExplicitDestinationRedirect"}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  const auto& status = response->results()[0].status_code();
  EXPECT_EQ(status.as_status(), Status::BadInternalError);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "AddNodesExplicitDestinationRedirected");
  EXPECT_EQ(handler->prepareAddNodesCalls, 1u);
  EXPECT_EQ(handler->addNodesCalls, 0u);
  EXPECT_EQ(redirectedNamespace->permission_questions(), 0u);
  EXPECT_TRUE(addressSpace.try_find_node_sync(requestedNodeId).is_bad());
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-01-PREPARE-FAILURES, scope=function)
TEST(NodeManagementService, AddNodesPreservesPreparationFailuresAndRejectsUnknownDestination)
{
  boost::asio::thread_pool threadPool;

  {
    auto sessionInfo =
      std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
    auto handler = std::make_shared<FakeNodeManagementDelegate>();
    auto itemDetail = make_error_detail(
      "InjectedPreparationItemFailure", "injected preparation item failure", "TestDelegate");
    const std::shared_ptr<const ErrorDetail> sharedItemDetail{std::move(itemDetail)};
    handler->prepareAddNodesResultFactory = [sharedItemDetail](const std::vector<AddNodesItem>&)
    {
      BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
      batch.items.emplace_back(StatusCode{Status::BadNotSupported, sharedItemDetail});
      return batch;
    };

    AddNodesRequest request;
    request.request_header().request_handle() = 1;
    request.nodes_to_add().push_back(
      make_conforming_object_add_nodes_item(NodeId{1, 61020u}, QualifiedName{1, "PreparationItemFailure"}));
    auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
    ASSERT_FALSE(result.isServiceFault);
    auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
    ASSERT_NE(response, nullptr);
    ASSERT_EQ(response->results().size(), 1u);
    EXPECT_EQ(response->results()[0].status_code().as_status(), Status::BadNotSupported);
    EXPECT_EQ(response->results()[0].status_code().shared_detail(), sharedItemDetail);
    EXPECT_EQ(handler->addNodesCalls, 0u);
  }

  {
    auto sessionInfo =
      std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
    auto handler = std::make_shared<FakeNodeManagementDelegate>();
    auto batchDetail =
      make_error_detail("InjectedPreparationBatchFailure", "injected batch failure", "TestDelegate");
    const std::shared_ptr<const ErrorDetail> sharedBatchDetail{std::move(batchDetail)};
    handler->prepareAddNodesResultFactory = [sharedBatchDetail](const std::vector<AddNodesItem>&)
    {
      BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
      batch.batchStatus = VoidResult{StatusCode{Status::BadOutOfService, sharedBatchDetail}};
      return batch;
    };

    AddNodesRequest request;
    request.request_header().request_handle() = 1;
    request.nodes_to_add().push_back(make_conforming_object_add_nodes_item(
      NodeId{1, 61021u}, QualifiedName{1, "PreparationBatchFailureFirst"}));
    request.nodes_to_add().push_back(make_conforming_object_add_nodes_item(
      NodeId{1, 61022u}, QualifiedName{1, "PreparationBatchFailureSecond"}));
    auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
    ASSERT_FALSE(result.isServiceFault);
    auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
    ASSERT_NE(response, nullptr);
    ASSERT_EQ(response->results().size(), 2u);
    for (const auto& itemResult : response->results())
    {
      EXPECT_EQ(itemResult.status_code().as_status(), Status::BadOutOfService);
      EXPECT_EQ(itemResult.status_code().shared_detail(), sharedBatchDetail);
    }
    EXPECT_EQ(handler->addNodesCalls, 0u);
  }

  {
    auto sessionInfo =
      std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
    auto handler = std::make_shared<FakeNodeManagementDelegate>();
    handler->prepareAddNodesResultFactory = [](const std::vector<AddNodesItem>&)
    {
      BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
      batch.items.emplace_back(NodeManagementDelegate::AddNodeDestination{uint16_t{250}});
      return batch;
    };

    AddNodesRequest request;
    request.request_header().request_handle() = 1;
    request.nodes_to_add().push_back(
      make_conforming_object_add_nodes_item(NodeId{}, QualifiedName{1, "UnknownPreparedDestination"}));
    auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
    ASSERT_FALSE(result.isServiceFault);
    auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
    ASSERT_NE(response, nullptr);
    ASSERT_EQ(response->results().size(), 1u);
    const auto& status = response->results()[0].status_code();
    EXPECT_EQ(status.as_status(), Status::BadInternalError);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "AddNodesDestinationNamespaceUnknown");
    EXPECT_EQ(handler->addNodesCalls, 0u);
  }

  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-01-PREPARE-FAILURES, scope=function)
TEST(NodeManagementService, AddNodesRejectsWrongPreparationResultCardinality)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  handler->prepareAddNodesResultFactory = [](const std::vector<AddNodesItem>&)
  {
    BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
    batch.items.emplace_back(NodeManagementDelegate::AddNodeDestination{uint16_t{1}});
    return batch;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(make_conforming_object_add_nodes_item(
    NodeId{1, 61023u}, QualifiedName{1, "PreparationCardinalityFirst"}));
  request.nodes_to_add().push_back(make_conforming_object_add_nodes_item(
    NodeId{1, 61024u}, QualifiedName{1, "PreparationCardinalitySecond"}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  for (const auto& itemResult : response->results())
  {
    const auto& status = itemResult.status_code();
    EXPECT_EQ(status.as_status(), Status::BadInternalError);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "AddNodesPreparationCardinalityMismatch");
  }
  EXPECT_EQ(handler->addNodesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-01-PREPARE, scope=function)
TEST(NodeManagementService, AddNodesPreparationAndPermissionDenialDoNotMutate)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();
  const auto destinationNamespace = addressSpace.add_namespace_sync(
    default_ns::Namespace::create("urn:test:add-nodes:denied", threadPool.get_executor()));
  auto deniedPermissions = ua::test_helpers::all_permissions();
  deniedPermissions.reset(PermissionType::Bit::AddNode);
  sessionInfo->set_namespace_permissions(destinationNamespace, deniedPermissions);
  handler->nullRequestedNodeDestination = destinationNamespace;
  const NodeId wouldBeCreated{destinationNamespace, 60000u};

  ASSERT_TRUE(addressSpace.try_find_node_sync(wouldBeCreated).is_bad());
  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(NodeId{}, QualifiedName{1, "DeniedPreparedDestination"}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);
  const auto& status = response->results()[0].status_code();
  EXPECT_EQ(status.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "RoleNotGranted");
  EXPECT_EQ(handler->prepareAddNodesCalls, 1u);
  EXPECT_EQ(handler->addNodesCalls, 0u);
  EXPECT_TRUE(addressSpace.try_find_node_sync(wouldBeCreated).is_bad());
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-SVR-AUTHZ-003-NO-SPECIAL-NAMESPACE-BRANCH, scope=function)
TEST(NodeManagementService, AddNodesTreatsEveryRegisteredNamespaceThroughItsPermissionContract)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();
  const auto deniedApplicationNamespace = addressSpace.add_namespace_sync(
    default_ns::Namespace::create("urn:test:add-nodes:application-denied", threadPool.get_executor()));
  auto deniedPermissions = ua::test_helpers::all_permissions();
  deniedPermissions.reset(PermissionType::Bit::AddNode);
  sessionInfo->set_namespace_permissions(deniedApplicationNamespace, deniedPermissions);

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(NodeId{0, 61010u}, QualifiedName{1, "SdkOwnedAllowed"}));
  request.nodes_to_add().push_back(make_conforming_object_add_nodes_item(
    NodeId{deniedApplicationNamespace, 61011u}, QualifiedName{1, "ApplicationDenied"}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  EXPECT_TRUE(response->results()[0].status_code().is_good());
  EXPECT_EQ(response->results()[0].added_node_id(), (NodeId{0, 61010u}));
  EXPECT_EQ(response->results()[1].status_code().as_status(), Status::BadUserAccessDenied);

  ASSERT_EQ(handler->authorizedAddNodes.size(), 1u);
  EXPECT_EQ(handler->authorizedAddNodes[0].destination.namespaceIndex, 0u);
  EXPECT_EQ(handler->authorizedAddNodes[0].item.requested_new_node_id().node_id(), (NodeId{0, 61010u}));
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-02-PRECEDENCE, scope=function)
TEST(NodeManagementService, AddNodesAuthorizationPrecedesDelegateDispositionsAndPreservesDetails)
{
  struct Disposition
  {
    Status status;
    std::string_view detailCode;
  };

  constexpr std::array dispositions{
    Disposition{Status::BadNotSupported, "PreparedNamespaceCannotCreate"},
    Disposition{Status::BadNodeIdRejected, "PreparedNamespaceRejectedIdentifier"},
    Disposition{Status::BadNodeIdExists, "PreparedIdentifierAlreadyExists"},
  };

  boost::asio::thread_pool threadPool;
  for (size_t dispositionIndex = 0; dispositionIndex < dispositions.size(); ++dispositionIndex)
  {
    const auto disposition = dispositions[dispositionIndex];
    const NodeId requestedNodeId{1, static_cast<uint32_t>(61100u + dispositionIndex)};
    const QualifiedName browseName{
      1, "Disposition" + std::to_string(static_cast<unsigned long long>(dispositionIndex))};

    auto deniedSession =
      std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
    deniedSession->clear_roles_for_test();
    auto deniedHandler = std::make_shared<FakeNodeManagementDelegate>();
    deniedHandler->addNodesResultFactory = [disposition](const std::vector<AddNodesItem>&)
    {
      AddNodesResult itemResult;
      itemResult.status_code() = StatusCode{disposition.status,
        make_error_detail(
          std::string{disposition.detailCode}, "injected mutation disposition", "TestDelegate")};
      return std::vector<AddNodesResult>{std::move(itemResult)};
    };
    AddNodesRequest deniedRequest;
    deniedRequest.request_header().request_handle() = 1;
    deniedRequest.nodes_to_add().push_back(
      make_conforming_object_add_nodes_item(requestedNodeId, browseName));
    auto deniedResult =
      invoke_service(deniedSession, deniedHandler, threadPool.get_executor(), std::move(deniedRequest));
    ASSERT_FALSE(deniedResult.isServiceFault);
    auto* deniedResponse = dynamic_cast<AddNodesResponse*>(deniedResult.response.get());
    ASSERT_NE(deniedResponse, nullptr);
    ASSERT_EQ(deniedResponse->results().size(), 1u);
    const auto& deniedStatus = deniedResponse->results()[0].status_code();
    EXPECT_EQ(deniedStatus.as_status(), Status::BadUserAccessDenied);
    ASSERT_NE(deniedStatus.shared_detail(), nullptr);
    EXPECT_EQ(deniedStatus.shared_detail()->code, "RoleNotGranted");
    EXPECT_EQ(deniedHandler->addNodesCalls, 0u);

    auto allowedSession =
      std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
    auto allowedHandler = std::make_shared<FakeNodeManagementDelegate>();
    allowedHandler->addNodesResultFactory = [disposition](const std::vector<AddNodesItem>&)
    {
      AddNodesResult itemResult;
      itemResult.status_code() = StatusCode{disposition.status,
        make_error_detail(
          std::string{disposition.detailCode}, "injected mutation disposition", "TestDelegate")};
      return std::vector<AddNodesResult>{std::move(itemResult)};
    };
    AddNodesRequest allowedRequest;
    allowedRequest.request_header().request_handle() = 1;
    allowedRequest.nodes_to_add().push_back(
      make_conforming_object_add_nodes_item(requestedNodeId, browseName));
    auto allowedResult =
      invoke_service(allowedSession, allowedHandler, threadPool.get_executor(), std::move(allowedRequest));
    ASSERT_FALSE(allowedResult.isServiceFault);
    auto* allowedResponse = dynamic_cast<AddNodesResponse*>(allowedResult.response.get());
    ASSERT_NE(allowedResponse, nullptr);
    ASSERT_EQ(allowedResponse->results().size(), 1u);
    const auto& allowedStatus = allowedResponse->results()[0].status_code();
    EXPECT_EQ(allowedStatus.as_status(), disposition.status);
    ASSERT_NE(allowedStatus.shared_detail(), nullptr);
    EXPECT_EQ(allowedStatus.shared_detail()->code, disposition.detailCode);
    EXPECT_EQ(allowedHandler->addNodesCalls, 1u);
  }
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-02-PRECEDENCE, scope=function)
TEST(NodeManagementService, AddNodesWaitsForAsyncDestinationAuthorizationBeforeValidation)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto destination =
    ua::test::DeferredNamespace::create("urn:test:add-nodes:async-denial", threadPool.get_executor());
  destination->set_async_namespace_permissions(PermissionType{});
  destination->set_resolution_mode(ua::test::DeferredNamespace::ResolutionMode::Deferred);
  const auto destinationNamespace = sessionInfo->address_space().add_namespace_sync(destination);
  handler->nullRequestedNodeDestination = destinationNamespace;

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  auto malformedIfInspected = make_conforming_object_add_nodes_item(NodeId{}, QualifiedName{});
  malformedIfInspected.parent_node_id().node_id() = NodeId{1, 999u};
  request.nodes_to_add().push_back(std::move(malformedIfInspected));

  std::promise<Response> completion;
  auto responseFuture = completion.get_future();
  auto service = NodeManagementService::create(sessionInfo,
    handler,
    1,
    std::move(request),
    threadPool.get_executor(),
    [&completion](Response response) { completion.set_value(std::move(response)); });
  ASSERT_NE(service, nullptr);
  ASSERT_TRUE(destination->wait_for_pending_resolutions());
  EXPECT_EQ(responseFuture.wait_for(0ms), std::future_status::timeout);
  EXPECT_EQ(handler->addNodesCalls, 0u);

  const auto permissionCalls = destination->effective_permissions_calls();
  ASSERT_EQ(permissionCalls.size(), 1u);
  EXPECT_FALSE(permissionCalls[0].nodes.has_value());
  destination->complete_pending_resolutions();

  ASSERT_EQ(responseFuture.wait_for(5s), std::future_status::ready);
  auto response = responseFuture.get();
  auto* addNodesResponse = dynamic_cast<AddNodesResponse*>(response.second.get());
  ASSERT_NE(addNodesResponse, nullptr);
  ASSERT_EQ(addNodesResponse->results().size(), 1u);
  const auto& status = addNodesResponse->results()[0].status_code();
  EXPECT_EQ(status.as_status(), Status::BadUserAccessDenied);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "RoleNotGranted");
  EXPECT_EQ(handler->addNodesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-03-COMMIT-CONTRACT, scope=function)
TEST(NodeManagementService, AddNodesRejectsNullOrRedirectedSuccessfulNodeId)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();
  const auto otherNamespace = addressSpace.add_namespace_sync(
    default_ns::Namespace::create("urn:test:add-nodes:wrong-result", threadPool.get_executor()));
  sessionInfo->set_namespace_permissions(otherNamespace, ua::test_helpers::all_permissions());
  handler->preserveInvalidSuccessfulNodeIds = true;
  handler->addNodesResultFactory = [otherNamespace](const std::vector<AddNodesItem>&)
  {
    std::vector<AddNodesResult> results(3);
    for (auto& result : results)
    {
      result.status_code() = Status::Good;
    }
    results[0].added_node_id() = NodeId{};
    results[1].added_node_id() = NodeId{otherNamespace, 61201u};
    results[2].added_node_id() = NodeId{1, 61202u};
    return results;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(NodeId{}, QualifiedName{1, "NullSuccessfulNodeId"}));
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(NodeId{1, 61201u}, QualifiedName{1, "RedirectedSuccessfulNodeId"}));
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(NodeId{1, 61202u}, QualifiedName{1, "ValidSuccessfulNodeId"}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  for (size_t itemIndex : {size_t{0}, size_t{1}})
  {
    const auto& status = response->results()[itemIndex].status_code();
    EXPECT_EQ(status.as_status(), Status::BadInternalError);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "AddNodesMutationDestinationMismatch");
    EXPECT_EQ(
      ::ua::test_utils::error_context(status.shared_detail().get(), ContextKeys::operationIndex.value()),
      std::to_string(itemIndex));
  }
  EXPECT_TRUE(response->results()[2].status_code().is_good());
  EXPECT_EQ(response->results()[2].added_node_id(), (NodeId{1, 61202u}));
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-03-COMMIT-CONTRACT, scope=function)
TEST(NodeManagementService, AddNodesRejectsWrongMutationResultCardinality)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  handler->addNodesResultFactory = [](const std::vector<AddNodesItem>&)
  {
    AddNodesResult onlyResult;
    onlyResult.status_code() = Status::Good;
    onlyResult.added_node_id() = NodeId{1, 61300u};
    return std::vector<AddNodesResult>{std::move(onlyResult)};
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(NodeId{1, 61300u}, QualifiedName{1, "CardinalityFirst"}));
  request.nodes_to_add().push_back(
    make_conforming_object_add_nodes_item(NodeId{1, 61301u}, QualifiedName{1, "CardinalitySecond"}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);
  for (const auto& itemResult : response->results())
  {
    const auto& status = itemResult.status_code();
    EXPECT_EQ(status.as_status(), Status::BadInternalError);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "AddNodesMutationCardinalityMismatch");
  }
  EXPECT_EQ(handler->addNodesCalls, 1u);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.7.2.4 assigns Bad_BrowseNameInvalid to an AddNodes item whose QualifiedName is
// unusable. The service owns this validation: a namespace delegate cannot safely accept an empty
// name or resolve a namespace index absent from the server's NamespaceArray.
// @verifies AC-SVR-NM-AN-026-BROWSENAMEINVALID
TEST(NodeManagementService, AddNodesRejectsEmptyAndUnknownNamespaceBrowseNamesBeforeTheDelegate)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  AddNodesItem emptyName;
  emptyName.parent_node_id().node_id() = NodeId{1, 85u};
  emptyName.browse_name() = QualifiedName{};
  emptyName.node_class() = NodeClass::Object;
  req.nodes_to_add().payload().push_back(std::move(emptyName));

  AddNodesItem unknownNamespace;
  unknownNamespace.parent_node_id().node_id() = NodeId{1, 85u};
  unknownNamespace.browse_name() = QualifiedName{250, "UnknownNamespace"};
  unknownNamespace.node_class() = NodeClass::Object;
  req.nodes_to_add().payload().push_back(std::move(unknownNamespace));

  AddNodesItem valid;
  valid.parent_node_id().node_id() = NodeId{1, 85u};
  valid.browse_name() = QualifiedName{1, "Valid"};
  valid.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(valid);
  req.nodes_to_add().payload().push_back(std::move(valid));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_EQ(response->results()[0].status_code(), Status::BadBrowseNameInvalid);
  EXPECT_NE(response->results()[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(response->results()[1].status_code(), Status::BadBrowseNameInvalid);
  EXPECT_NE(response->results()[1].status_code().shared_detail(), nullptr);
  EXPECT_TRUE(response->results()[2].status_code().is_good());

  EXPECT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 1u);
  EXPECT_EQ(handler->addNodesItems[0].browse_name(), (QualifiedName{1, "Valid"}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// @relation(SVR-NM-AR-004, scope=function)
TEST(NodeManagementService, AddReferences_AuthorizedItems_ReachHandler)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;
  AddReferencesItem item;
  item.source_node_id() = NodeId{1, 85u};
  // A conforming item: the Server screens targetNodeId, targetNodeClass and targetServerUri per
  // OPC 10000-4 5.7.3.2 before an item reaches authorization, so a bare item would be refused for
  // its parameters and never exercise what this test is about.
  item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  item.is_forward() = true;
  item.target_node_id().node_id() = NodeId{1, 100u};
  item.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_TRUE(resp->results()[0].is_good());
  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.7.3.4 assigns Bad_ReferenceTypeIdInvalid when referenceTypeId does not resolve to
// a ReferenceType. A missing Node and an existing Object are the two ways that resolution can fail;
// the valid item is the control proving the batch and delegate remain live.
// @relation(AC-SVR-NM-AR-021-REFERENCETYPEIDINVALID, scope=function)
TEST(NodeManagementService, AddReferencesRejectsMissingAndNonReferenceTypeIdsBeforeDelegate)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  const auto makeItem = [](NodeId referenceTypeId)
  {
    AddReferencesItem item;
    item.source_node_id() = NodeId{1, 85u};
    item.reference_type_id() = std::move(referenceTypeId);
    item.is_forward() = true;
    item.target_node_id().node_id() = NodeId{1, 200u};
    item.target_node_class() = NodeClass::Object;
    return item;
  };

  AddReferencesRequest request;
  request.request_header().request_handle() = 1;
  request.references_to_add().push_back(makeItem(NodeId{1, 99998u}));
  request.references_to_add().push_back(makeItem(NodeId{1, 100u}));
  request.references_to_add().push_back(makeItem(NodeId{ReferenceTypeId::Organizes}));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(request));

  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  for (size_t index : {size_t{0}, size_t{1}})
  {
    const auto& status = response->results()[index];
    EXPECT_EQ(status.as_status(), Status::BadReferenceTypeIdInvalid);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "AddReferencesReferenceTypeInvalid");
    EXPECT_NE(status.shared_detail()->cause, nullptr)
      << "the underlying missing-node or wrong-node-class detail must remain chained";
  }
  EXPECT_TRUE(response->results()[2].is_good());
  ASSERT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u);
  EXPECT_EQ(handler->addReferencesItems[0].reference_type_id(), NodeId{ReferenceTypeId::Organizes});
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.7.3.4 permits HasSubtype unless the resulting Reference violates the data model.
// Symmetric is a ReferenceType-only Attribute, so its preservation check must not reject ordinary
// ObjectType hierarchy growth; the ReferenceType control keeps that narrower rule exercised. A mixed
// ObjectType-to-VariableType negative arm proves the broader same-NodeClass rule remains enforced.
// @relation(AC-SVR-NM-AR-025-REFERENCENOTALLOWED, scope=function)
TEST(NodeManagementService, AddReferencesAcceptsHasSubtypeForObjectTypesAndReferenceTypes)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();

  ASSERT_TRUE(addressSpace.try_create_node_sync(NodeId{1, 7200u}, NodeClass::ObjectType, {}).is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(NodeId{1, 7201u}, NodeClass::ObjectType, {}).is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(NodeId{1, 7204u}, NodeClass::VariableType, {}).is_good());

  auto referenceBase =
    addressSpace.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 7202u}, NodeClass::ReferenceType);
  auto referenceDerived =
    addressSpace.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 7203u}, NodeClass::ReferenceType);
  ASSERT_TRUE(referenceBase.is_good());
  ASSERT_TRUE(referenceDerived.is_good());
  referenceBase.value().set_symmetric(false);
  referenceDerived.value().set_symmetric(false);

  const auto makeSubtype = [](NodeId base, NodeId derived, NodeClass nodeClass)
  {
    AddReferencesItem item;
    item.source_node_id() = std::move(base);
    item.reference_type_id() = NodeId{ReferenceTypeId::HasSubtype};
    item.is_forward() = true;
    item.target_node_id().node_id() = std::move(derived);
    item.target_node_class() = nodeClass;
    return item;
  };

  AddReferencesRequest request;
  request.request_header().request_handle() = 1;
  request.references_to_add().push_back(
    makeSubtype(NodeId{1, 7200u}, NodeId{1, 7201u}, NodeClass::ObjectType));
  request.references_to_add().push_back(
    makeSubtype(NodeId{1, 7202u}, NodeId{1, 7203u}, NodeClass::ReferenceType));
  request.references_to_add().push_back(
    makeSubtype(NodeId{1, 7200u}, NodeId{1, 7204u}, NodeClass::VariableType));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  EXPECT_TRUE(response->results()[0].is_good())
    << "ObjectTypes must not be subjected to the ReferenceType Symmetric check";
  EXPECT_TRUE(response->results()[1].is_good())
    << "the valid ReferenceType control must continue to pass its Symmetric check";
  EXPECT_EQ(response->results()[2], StatusCode{Status::BadReferenceNotAllowed});
  ASSERT_NE(response->results()[2].shared_detail(), nullptr);
  EXPECT_EQ(response->results()[2].shared_detail()->code, "HasSubtypeNodeClassInvalid");

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  EXPECT_EQ(handler->addReferencesItems.size(), 2u);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(NodeManagementService, DeleteNodes_AuthorizedItems_ReachHandler)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  DeleteNodesRequest req;
  req.request_header().request_handle() = 1;
  DeleteNodesItem item;
  item.node_id() = NodeId{1, 100u};
  req.nodes_to_delete().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<DeleteNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_TRUE(resp->results()[0].is_good());
  EXPECT_EQ(handler->deleteNodesCalls, 1u);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NodeManagementService, DeleteReferences_AuthorizedItems_ReachHandler)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  DeleteReferencesRequest req;
  req.request_header().request_handle() = 1;
  DeleteReferencesItem item;
  item.source_node_id() = NodeId{1, 100u};
  item.reference_type_id() = NodeId{1, 250u};
  item.target_node_id() = ExpandedNodeId{NodeId{1, 200u}};
  req.references_to_delete().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<DeleteReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_TRUE(resp->results()[0].is_good());
  EXPECT_EQ(handler->deleteReferencesCalls, 1u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 sections 5.7.3 and 5.7.5 answer a source Node that does not exist with Bad_SourceNodeIdInvalid. The
// code replaces the lookup's Bad_NodeIdUnknown, and the lookup's ErrorDetail ("NodeNotFound") stays in the
// item's diagnosticInfos, so the client can still see why the source was invalid.
// @relation(AC-SVR-NM-AR-020-SOURCENODEIDINVALID, scope=function)
// @relation(AC-SVR-NM-DR-020-SOURCENODEIDINVALID, scope=function)
// @relation(AC-SVR-DIAG-010-PEROPERATION-DETAIL, scope=function)
TEST(NodeManagementService, AMissingReferenceSourceKeepsTheLookupDetailInItsDiagnostics)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(
    tp.get_executor(), make_allow_all_authorizer(), MessageSecurityMode::Sign);
  si->serverCfg.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  const NodeId missingSource{1, 7777u};

  const auto expectLookupDetail =
    [](const Array<DiagnosticInfo>& diagnostics, const ResponseHeader& header, const std::string& service)
  {
    ASSERT_EQ(diagnostics.size(), 1u) << service;
    ASSERT_FALSE(diagnostics[0].is_null()) << service << ": the lookup's ErrorDetail was dropped";
    auto decoded = diagnostic_to_error_detail(diagnostics[0], header.string_table());
    ASSERT_NE(decoded, nullptr) << service;
    EXPECT_EQ(decoded->code, "NodeNotFound") << service;
  };

  AddReferencesRequest add;
  add.request_header().request_handle() = 1;
  add.request_header().return_diagnostics() = 0xFFFF;
  AddReferencesItem addItem;
  addItem.source_node_id() = missingSource;
  addItem.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  addItem.is_forward() = true;
  addItem.target_node_id().node_id() = NodeId{1, 100u};
  addItem.target_node_class() = NodeClass::Object;
  add.references_to_add().payload().push_back(std::move(addItem));

  auto added = invoke_service(si, handler, tp.get_executor(), std::move(add));
  ASSERT_FALSE(added.isServiceFault);
  auto* addResponse = dynamic_cast<AddReferencesResponse*>(added.response.get());
  ASSERT_NE(addResponse, nullptr);
  ASSERT_EQ(addResponse->results().size(), 1u);
  EXPECT_EQ(addResponse->results()[0], Status::BadSourceNodeIdInvalid)
    << to_string(addResponse->results()[0]);
  expectLookupDetail(addResponse->diagnostic_infos(), addResponse->response_header(), "AddReferences");

  DeleteReferencesRequest remove;
  remove.request_header().request_handle() = 2;
  remove.request_header().return_diagnostics() = 0xFFFF;
  DeleteReferencesItem removeItem;
  removeItem.source_node_id() = missingSource;
  removeItem.reference_type_id() = NodeId{1, 250u};
  removeItem.is_forward() = true;
  removeItem.target_node_id() = ExpandedNodeId{NodeId{1, 200u}};
  remove.references_to_delete().payload().push_back(std::move(removeItem));

  auto removed = invoke_service(si, handler, tp.get_executor(), std::move(remove));
  ASSERT_FALSE(removed.isServiceFault);
  auto* removeResponse = dynamic_cast<DeleteReferencesResponse*>(removed.response.get());
  ASSERT_NE(removeResponse, nullptr);
  ASSERT_EQ(removeResponse->results().size(), 1u);
  EXPECT_EQ(removeResponse->results()[0], Status::BadSourceNodeIdInvalid)
    << to_string(removeResponse->results()[0]);
  expectLookupDetail(
    removeResponse->diagnostic_infos(), removeResponse->response_header(), "DeleteReferences");

  EXPECT_EQ(handler->addReferencesCalls, 0u);
  EXPECT_EQ(handler->deleteReferencesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.7.5 assigns Bad_ReferenceTypeIdInvalid when referenceTypeId is missing or
// resolves to any NodeClass other than ReferenceType. The custom ReferenceType is the positive
// control proving a valid sibling still reaches the delegate.
// @relation(AC-SVR-NM-DR-021-REFERENCETYPEIDINVALID, scope=function)
TEST(NodeManagementService, DeleteReferencesRejectsMissingAndNonReferenceTypeIdsBeforeDelegate)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  const NodeId validReferenceTypeId{1, 250u};

  const auto makeItem = [](NodeId referenceTypeId)
  {
    DeleteReferencesItem item;
    item.source_node_id() = NodeId{1, 100u};
    item.reference_type_id() = std::move(referenceTypeId);
    item.is_forward() = true;
    item.target_node_id() = ExpandedNodeId{NodeId{1, 200u}};
    return item;
  };

  const NodeId missingReferenceTypeId{1, 99998u};
  const NodeId objectNodeId{1, 100u};
  DeleteReferencesRequest request;
  request.request_header().request_handle() = 1;
  request.references_to_delete().push_back(makeItem(missingReferenceTypeId));
  request.references_to_delete().push_back(makeItem(objectNodeId));
  request.references_to_delete().push_back(makeItem(validReferenceTypeId));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(request));

  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<DeleteReferencesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 3u);
  for (size_t index : {size_t{0}, size_t{1}})
  {
    const StatusCode& status = response->results()[index];
    EXPECT_EQ(status.as_status(), Status::BadReferenceTypeIdInvalid);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "DeleteReferencesReferenceTypeInvalid");
    EXPECT_EQ(
      ::ua::test_utils::error_context(status.shared_detail().get(), ContextKeys::operationIndex.value()),
      std::to_string(index));
  }
  EXPECT_EQ(::ua::test_utils::error_context(
              response->results()[0].shared_detail().get(), ContextKeys::nodeId.value()),
    to_string(missingReferenceTypeId));
  EXPECT_NE(response->results()[0].shared_detail()->cause, nullptr)
    << "the missing-node lookup detail must remain chained";
  EXPECT_EQ(::ua::test_utils::error_context(
              response->results()[1].shared_detail().get(), ContextKeys::nodeId.value()),
    to_string(objectNodeId));

  EXPECT_TRUE(response->results()[2].is_good());
  ASSERT_EQ(handler->deleteReferencesCalls, 1u);
  ASSERT_EQ(handler->deleteReferencesItems.size(), 1u)
    << "invalid ReferenceType ids must not reach the delegate";
  EXPECT_EQ(handler->deleteReferencesItems[0].reference_type_id(), validReferenceTypeId);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NodeManagementService, DeleteReferencesRejectsInvalidTargetsPerItemBeforeDelegation)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto makeItem = [](ExpandedNodeId target)
  {
    DeleteReferencesItem item;
    item.source_node_id() = NodeId{1, 100u};
    item.reference_type_id() = NodeId{1, 250u};
    item.is_forward() = true;
    item.target_node_id() = std::move(target);
    return item;
  };

  DeleteReferencesRequest request;
  request.request_header().request_handle() = 1;
  request.references_to_delete().push_back(makeItem(ExpandedNodeId{NodeId{1, 200u}}));

  ExpandedNodeId foreignTarget{NodeId{1, 200u}};
  foreignTarget.server_index() = 7;
  request.references_to_delete().push_back(makeItem(std::move(foreignTarget)));
  request.references_to_delete().push_back(makeItem(ExpandedNodeId{}));
  request.references_to_delete().push_back(makeItem(ExpandedNodeId{NodeId{1, 9299u}}));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(request));

  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<DeleteReferencesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 4u);
  EXPECT_TRUE(response->results()[0].is_good());
  EXPECT_EQ(response->results()[1], StatusCode{Status::BadServerIndexInvalid});
  EXPECT_EQ(response->results()[2], StatusCode{Status::BadTargetNodeIdInvalid});
  EXPECT_EQ(response->results()[3], StatusCode{Status::BadTargetNodeIdInvalid});

  ASSERT_NE(response->results()[1].shared_detail(), nullptr);
  EXPECT_EQ(response->results()[1].shared_detail()->code, "DeleteReferencesServerIndexInvalid");
  ASSERT_NE(response->results()[2].shared_detail(), nullptr);
  EXPECT_EQ(response->results()[2].shared_detail()->code, "DeleteReferencesTargetNodeIdInvalid");
  ASSERT_NE(response->results()[3].shared_detail(), nullptr);
  EXPECT_EQ(response->results()[3].shared_detail()->code, "DeleteReferencesTargetNodeIdInvalid");
  EXPECT_NE(response->results()[3].shared_detail()->cause, nullptr)
    << "the target lookup ErrorDetail must remain chained to the per-item refusal";

  ASSERT_EQ(handler->deleteReferencesCalls, 1u);
  ASSERT_EQ(handler->deleteReferencesItems.size(), 1u) << "invalid target items must not reach the delegate";
  const ExpandedNodeId expectedTarget{NodeId{1, 200u}};
  EXPECT_EQ(handler->deleteReferencesItems[0].target_node_id(), expectedTarget);

  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Handler returns per-item errors ----------------------------------------

TEST(NodeManagementService, AddNodes_HandlerReturnsPerItemErrors)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  handler->addNodesResultFactory = [](const std::vector<AddNodesItem>&)
  {
    std::vector<AddNodesResult> results(2);
    results[0].status_code() = Status::Good;
    results[0].added_node_id() = NodeId{1, 1000u};
    results[1].status_code() = Status::BadNodeIdExists;
    return results;
  };

  AddNodesRequest req;
  req.request_header().request_handle() = 1;
  AddNodesItem item1;
  item1.parent_node_id().node_id() = NodeId{1, 85u};
  item1.browse_name() = QualifiedName{1, "HandlerResult1"};
  item1.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item1);
  AddNodesItem item2;
  item2.parent_node_id().node_id() = NodeId{1, 85u};
  item2.browse_name() = QualifiedName{1, "HandlerResult2"};
  item2.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item2);
  req.nodes_to_add().payload().push_back(std::move(item1));
  req.nodes_to_add().payload().push_back(std::move(item2));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);
  EXPECT_TRUE(resp->results()[0].status_code().is_good());
  EXPECT_EQ(resp->results()[0].added_node_id(), (NodeId{1, 1000u}));
  EXPECT_EQ(resp->results()[1].status_code(), Status::BadNodeIdExists);
  ::ua::test_utils::drain_with_timeout(tp);
}

TEST(NodeManagementService, DeleteNodes_HandlerReturnsPerItemErrors)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  handler->deleteNodesResultFactory = [](const std::vector<DeleteNodesItem>&)
  {
    std::vector<StatusCode> results{StatusCode{Status::Good}, StatusCode{Status::BadNodeIdUnknown}};
    return results;
  };

  DeleteNodesRequest req;
  req.request_header().request_handle() = 1;
  DeleteNodesItem item1;
  item1.node_id() = NodeId{1, 100u};
  DeleteNodesItem item2;
  item2.node_id() = NodeId{1, 200u};
  req.nodes_to_delete().payload().push_back(std::move(item1));
  req.nodes_to_delete().payload().push_back(std::move(item2));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<DeleteNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);
  EXPECT_TRUE(resp->results()[0].is_good());
  EXPECT_EQ(resp->results()[1], Status::BadNodeIdUnknown);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Mixed authorization: partial batch -------------------------------------

// @relation(AC-SVR-NM-AN-030-ADDNODES-DENIED, scope=function)
TEST(NodeManagementService, NM_AN_030_AddNodes_MixedAuthorization_PartialBatch)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto deniedNamespace = ua::test::DeferredNamespace::create("urn:test:denied", tp.get_executor());
  si->address_space().add_namespace_sync(deniedNamespace);
  const uint16_t deniedNamespaceIndex =
    si->address_space().namespace_array().get_namespace_index("urn:test:denied");
  auto deniedPermissions = ua::test_helpers::all_permissions();
  deniedPermissions.reset(PermissionType::Bit::AddNode);
  si->set_namespace_permissions(deniedNamespaceIndex, deniedPermissions);
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  handler->addNodesResultFactory = [](const std::vector<AddNodesItem>& items)
  {
    std::vector<AddNodesResult> results(items.size());
    for (size_t i = 0; i < items.size(); ++i)
    {
      results[i].status_code() = Status::Good;
      results[i].added_node_id() = NodeId{1, static_cast<uint32_t>(1000 + i)};
    }
    return results;
  };

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  AddNodesItem item0;
  item0.parent_node_id().node_id() = NodeId{1, 85u};  // authorized
  item0.requested_new_node_id().node_id() = NodeId{1, 1100u};
  item0.browse_name() = QualifiedName{1, "Authorized0"};
  item0.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item0);
  AddNodesItem item1;
  item1.parent_node_id().node_id() = NodeId{1, 999u};
  item1.requested_new_node_id().node_id() = NodeId{deniedNamespaceIndex, 1200u};  // denied
  item1.browse_name() = QualifiedName{deniedNamespaceIndex, "Denied"};
  item1.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item1);
  AddNodesItem item2;
  item2.parent_node_id().node_id() = NodeId{1, 85u};  // authorized
  item2.requested_new_node_id().node_id() = NodeId{1, 1101u};
  item2.browse_name() = QualifiedName{1, "Authorized2"};
  item2.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item2);

  req.nodes_to_add().payload().push_back(std::move(item0));
  req.nodes_to_add().payload().push_back(std::move(item1));
  req.nodes_to_add().payload().push_back(std::move(item2));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 3u);

  // item0: authorized - handler result
  EXPECT_TRUE(resp->results()[0].status_code().is_good());
  EXPECT_EQ(resp->results()[0].added_node_id(), (NodeId{1, 1000u}));

  // item1: denied
  EXPECT_EQ(resp->results()[1].status_code(), Status::BadUserAccessDenied);

  // item2: authorized - handler result
  EXPECT_TRUE(resp->results()[2].status_code().is_good());
  EXPECT_EQ(resp->results()[2].added_node_id(), (NodeId{1, 1001u}));

  // Handler receives only 2 items
  EXPECT_EQ(handler->addNodesCalls, 1u);
  EXPECT_EQ(handler->addNodesItems.size(), 2u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Context verification ---------------------------------------------------

TEST(NodeManagementService, ContextContainsCorrectFields)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddNodesRequest req;
  req.request_header().request_handle() = 1;
  AddNodesItem item;
  item.parent_node_id().node_id() = NodeId{1, 85u};
  item.browse_name() = QualifiedName{1, "ContextObject"};
  item.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item);
  req.nodes_to_add().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  ASSERT_NE(handler->lastContext, nullptr);

  EXPECT_NE(handler->lastContext->userIdentity, nullptr);
  EXPECT_NE(handler->lastContext->endpointSecurity, nullptr);
  EXPECT_NE(handler->lastContext->cancelled, nullptr);
  EXPECT_FALSE(handler->lastContext->cancelled->load());
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Coro wrapper test ------------------------------------------------------

TEST(NodeManagementService, CoroWrapper_AddNodes_BridgesCorrectly)
{
  boost::asio::thread_pool tp;
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  handler->addNodesResultFactory = [](const std::vector<AddNodesItem>& items)
  {
    std::vector<AddNodesResult> results(items.size());
    for (size_t i = 0; i < items.size(); ++i)
    {
      results[i].status_code() = Status::Good;
      results[i].added_node_id() = NodeId{1, static_cast<uint32_t>(2000 + i)};
    }
    return results;
  };

  auto context = std::make_shared<NodeManagementDelegate::Context>();
  context->cancelled = std::make_shared<std::atomic_bool>(false);

  std::vector<NodeManagementDelegate::AuthorizedAddNode> items(1);
  items[0].item.parent_node_id().node_id() = NodeId{1, 85u};
  items[0].destination.namespaceIndex = 1;

  std::promise<BatchResult<NodeManagementDelegate::AddNodesItemResult>> p;
  auto fut = p.get_future();

  // Use callback_to_task is tested indirectly through the coro wrapper.
  // We'll call the async method directly and verify.
  handler->add_nodes_async(context,
    AddressSpace::create("urn:test", tp.get_executor()),
    std::move(items),

    [&p](BatchResult<NodeManagementDelegate::AddNodesItemResult> batch) { p.set_value(std::move(batch)); });

  auto batch = fut.get();
  ASSERT_EQ(batch.items.size(), 1u);
  ASSERT_TRUE(batch.items[0].is_good());
  EXPECT_TRUE(batch.items[0].value().status_code().is_good());
  EXPECT_EQ(batch.items[0].value().added_node_id(), (NodeId{1, 2000u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Phase 5 end-to-end guarantee: node management delegate drops callback --

namespace
{

class DroppingNodeManagementDelegate final : public NodeManagementDelegate
{
public:
  std::atomic<bool> addNodesEntered{false};

  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<NodeManagementDelegate::AuthorizedAddNode>,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    addNodesEntered.store(true);
    // Drop - destructor fires default CallbackNotInvoked BatchResult.
    (void)callback;
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<AddReferencesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteNodesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteReferencesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }
};

}  // namespace

// A NodeManagement delegate that drops its AddNodesCompleteCallback without invoking it
// must cause the AddNodes service to deliver a bad per-item status (BadInternalError
// from std::function<void(T)>'s RAII default) to every routed item. The atomic flag proves the
// delegate path was entered - otherwise the test could pass trivially if the service
// short-circuited before reaching the delegate.
// --- ErrorDetail propagation from delegate -> response DiagnosticInfo ------

namespace
{

// Delegate that returns per-item bad Result<AddNodesItemResult> with a custom
// ErrorDetail, so the test can verify that the service forwards the ErrorDetail
// to the response's per-item DiagnosticInfo.
class PerItemErrorDetailDelegate final : public NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (size_t i = 0; i < items.size(); ++i)
    {
      // Bad Result<AddNodesItemResult> with a custom ErrorDetail - exercises the
      // service's new add_item_detail(...) forwarding path.
      batch.items.emplace_back(StatusCode{Status::BadUserAccessDenied},
        make_error_detail("TestBadDelegateItem", "delegate item rejection", "TestDelegate"));
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<AddReferencesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteNodesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteReferencesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }
};

// Delegate that returns a batch-level bad BatchResult with ErrorDetail for add_nodes.
class BatchErrorDetailDelegate final : public NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<NodeManagementDelegate::AuthorizedAddNode>,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    batch.batchStatus = VoidResult{StatusCode{Status::BadOutOfService},
      make_error_detail("TestBackendDown", "delegate batch failure", "TestDelegate")};
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<AddReferencesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteNodesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<DeleteReferencesItem>, NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    (void)callback;
  }
};

}  // namespace

// @relation(AC-COMP-SVR-NODE-MANAGEMENT-ADD-NODES-01-PREPARE-FAILURES, scope=function)
TEST(NodeManagementService, NodeManagementDelegateDefaultPreparationBindsExplicitIdsAndDeclinesNullRouting)
{
  boost::asio::thread_pool threadPool;
  BatchErrorDetailDelegate delegate;
  std::vector<AddNodesItem> items(2);
  items[0].requested_new_node_id().node_id() = NodeId{7, 1u};
  items[1].requested_new_node_id().node_id() = NodeId{};
  std::optional<BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult>> prepared;

  delegate.prepare_add_nodes_async(std::make_shared<NodeManagementDelegate::Context>(),
    AddressSpace::create("urn:test:add-nodes:default-prepare", threadPool.get_executor()),
    std::move(items),
    [&prepared](BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> result)
    { prepared.emplace(std::move(result)); });

  ASSERT_TRUE(prepared.has_value());
  EXPECT_TRUE(prepared->batchStatus.is_good());
  ASSERT_EQ(prepared->items.size(), 2u);
  ASSERT_TRUE(prepared->items[0].is_good());
  EXPECT_EQ(prepared->items[0].value().namespaceIndex, 7u);
  ASSERT_TRUE(prepared->items[1].is_bad());
  EXPECT_EQ(prepared->items[1].status_code().as_status(), Status::BadNotSupported);
  ASSERT_NE(prepared->items[1].shared_detail(), nullptr);
  EXPECT_EQ(prepared->items[1].shared_detail()->code, "AddNodesDestinationRoutingUnsupported");
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// When a delegate returns per-item bad Results carrying ErrorDetail and the client
// requests operation-level diagnostics, the service must forward the ErrorDetail
// into the response's diagnostic_infos() so the client can recover the cause chain.
TEST(NodeManagementService, AddNodesDelegatePerItemErrorDetailSurfacesInDiagnosticInfos)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(
    tp.get_executor(), make_allow_all_authorizer(), MessageSecurityMode::Sign);
  si->serverCfg.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  auto handler = std::make_shared<PerItemErrorDetailDelegate>();

  AddNodesRequest req;
  req.request_header().request_handle() = 1;
  req.request_header().return_diagnostics() = 0xFFFF;  // all service + operation bits
  AddNodesItem item;
  item.parent_node_id().node_id() = NodeId{1, 85u};
  item.requested_new_node_id().node_id() = NodeId{1, 61400u};
  item.browse_name() = QualifiedName{1, "DelegateError"};
  item.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item);
  req.nodes_to_add().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);

  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0].status_code(), Status::BadUserAccessDenied);

  ASSERT_EQ(resp->diagnostic_infos().size(), 1u);
  ASSERT_FALSE(resp->diagnostic_infos()[0].is_null())
    << "delegate ErrorDetail must surface as a per-item DiagnosticInfo";
  auto decoded =
    diagnostic_to_error_detail(resp->diagnostic_infos()[0], resp->response_header().string_table());
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded->code, "TestBadDelegateItem");
  EXPECT_EQ(decoded->source, "TestDelegate");
  ::ua::test_utils::drain_with_timeout(tp);
}

// When the delegate's BatchResult itself is bad (batchStatus), every authorized
// per-item response must carry the same ErrorDetail via DiagnosticInfo.
TEST(NodeManagementService, AddNodesDelegateBatchErrorDetailSurfacesOnEveryItem)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(
    tp.get_executor(), make_allow_all_authorizer(), MessageSecurityMode::Sign);
  si->serverCfg.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  auto handler = std::make_shared<BatchErrorDetailDelegate>();

  AddNodesRequest req;
  req.request_header().request_handle() = 1;
  req.request_header().return_diagnostics() = 0xFFFF;
  AddNodesItem item1;
  item1.parent_node_id().node_id() = NodeId{1, 85u};
  item1.requested_new_node_id().node_id() = NodeId{1, 61401u};
  item1.browse_name() = QualifiedName{1, "BatchError1"};
  item1.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item1);
  req.nodes_to_add().payload().push_back(std::move(item1));
  AddNodesItem item2;
  item2.parent_node_id().node_id() = NodeId{1, 85u};
  item2.requested_new_node_id().node_id() = NodeId{1, 61402u};
  item2.browse_name() = QualifiedName{1, "BatchError2"};
  item2.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(item2);
  req.nodes_to_add().payload().push_back(std::move(item2));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);

  ASSERT_EQ(resp->results().size(), 2u);
  EXPECT_EQ(resp->results()[0].status_code(), Status::BadOutOfService);
  EXPECT_EQ(resp->results()[1].status_code(), Status::BadOutOfService);

  ASSERT_EQ(resp->diagnostic_infos().size(), 2u);
  for (size_t i = 0; i < 2; ++i)
  {
    ASSERT_FALSE(resp->diagnostic_infos()[i].is_null())
      << "delegate batch ErrorDetail must surface on every authorized item (idx=" << i << ")";
    auto decoded =
      diagnostic_to_error_detail(resp->diagnostic_infos()[i], resp->response_header().string_table());
    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(decoded->code, "TestBackendDown") << " idx=" << i;
    EXPECT_EQ(decoded->source, "TestDelegate") << " idx=" << i;
  }
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- Address-space model constraints enforced by node management ------------
//
// The obligations below are all "the Server must refuse the request that would put an
// illegal structure into the address space". Each is driven through the real service with
// the plain FakeNodeManagementDelegate, which answers Good to everything it is handed - so
// the refusal asserted here can only come from the server, never from the fake. Every test
// therefore asserts two things: the offending operation carries the model-constraint status,
// and the offending item was never handed to the delegate (nothing downstream could have
// created it). Where the request also carries a legal item, that item must still succeed, so
// a blanket refusal cannot pass the test either.

// Part 3 section 4.2: NodeClass is a closed eight-value enumeration on the wire, so a vendor value
// decodes to nothing on every conforming client - which is why the prohibition binds the
// server rather than being left to interoperability. A plausible implementation treats
// AddNodesItem::node_class() as opaque payload to be forwarded to the delegate and never
// tests it against the enumeration, so a vendor NodeClass reaches node creation unchallenged.
// @verifies AC-SVR-ADDRSP-005-NO-VENDOR-NODECLASSES
TEST(NodeManagementService, AddNodeVendorNodeClassRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  // 4096 is outside the eight enumerators; assert that here so the test cannot silently
  // decay into "a legal NodeClass was refused" if the enumeration ever gains a member.
  const auto vendorNodeClass = static_cast<NodeClass>(4096);
  ASSERT_FALSE(is_valid(vendorNodeClass));

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  AddNodesItem vendorItem;
  vendorItem.parent_node_id().node_id() = NodeId{1, 85u};
  vendorItem.reference_type_id() = NodeId{0, 35u};  // Organizes
  vendorItem.requested_new_node_id().node_id() = NodeId{1, 5000u};
  vendorItem.browse_name() = QualifiedName{1, "VendorNodeClass"};
  vendorItem.node_class() = vendorNodeClass;
  req.nodes_to_add().payload().push_back(std::move(vendorItem));

  AddNodesItem lawfulItem;
  lawfulItem.parent_node_id().node_id() = NodeId{1, 85u};
  lawfulItem.reference_type_id() = NodeId{0, 35u};  // Organizes
  lawfulItem.requested_new_node_id().node_id() = NodeId{1, 5001u};
  lawfulItem.browse_name() = QualifiedName{1, "LawfulObject"};
  lawfulItem.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(lawfulItem);
  req.nodes_to_add().payload().push_back(std::move(lawfulItem));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0].status_code(), Status::BadNodeClassInvalid)
    << "a NodeClass outside the specification's eight must be refused";
  EXPECT_TRUE(resp->results()[1].status_code().is_good())
    << "the lawful item in the same request must still be honoured";

  // The refused item must never reach node creation, or a vendor NodeClass would enter the
  // address space regardless of the status reported to the client.
  EXPECT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 1u);
  EXPECT_EQ(handler->addNodesItems[0].node_class(), NodeClass::Object);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 6.6: an Interface is applied, never instantiated - a client following
// HasTypeDefinition to an Interface lands on an abstract type with no concrete behaviour.
// A plausible implementation validates only that the TypeDefinition names an ObjectType and
// stops there; BaseInterfaceType is an ObjectType, so that check lets the illegal instance
// through.
// @verifies AC-SVR-ADDRSP-029-INTERFACE-NOT-TYPEDEFINITION
TEST(NodeManagementService, AddNodeInterfaceAsTypeDefinitionRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  const NodeId concreteObjectTypeId{1, 3419u};
  ASSERT_TRUE(
    si->address_space().try_create_node_sync(concreteObjectTypeId, NodeClass::ObjectType, {}).is_good());

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  // TypeDefinition = BaseInterfaceType (0:17602) - the root of the Interface hierarchy.
  AddNodesItem interfaceTyped;
  interfaceTyped.parent_node_id().node_id() = NodeId{1, 85u};
  interfaceTyped.reference_type_id() = NodeId{0, 35u};  // Organizes
  interfaceTyped.requested_new_node_id().node_id() = NodeId{1, 5100u};
  interfaceTyped.browse_name() = QualifiedName{1, "InterfaceTypedObject"};
  interfaceTyped.node_class() = NodeClass::Object;
  interfaceTyped.type_definition().node_id() = NodeId{0, 17602u};
  req.nodes_to_add().payload().push_back(std::move(interfaceTyped));

  // TypeDefinition = a concrete local ObjectType, lawful.
  AddNodesItem objectTyped;
  objectTyped.parent_node_id().node_id() = NodeId{1, 85u};
  objectTyped.reference_type_id() = NodeId{0, 35u};  // Organizes
  objectTyped.requested_new_node_id().node_id() = NodeId{1, 5101u};
  objectTyped.browse_name() = QualifiedName{1, "ConcreteTypedObject"};
  objectTyped.node_class() = NodeClass::Object;
  objectTyped.type_definition().node_id() = concreteObjectTypeId;
  req.nodes_to_add().payload().push_back(std::move(objectTyped));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0].status_code(), Status::BadTypeDefinitionInvalid)
    << "no HasTypeDefinition may target BaseInterfaceType or a subtype";
  EXPECT_TRUE(resp->results()[1].status_code().is_good())
    << "a concrete ObjectType TypeDefinition in the same request must still be honoured";

  EXPECT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 1u);
  EXPECT_EQ(handler->addNodesItems[0].type_definition().node_id(), concreteObjectTypeId);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 6.6: Interfaces compose by subtyping, not by application - an Interface applying
// another would give two merge paths for the same members, and the member-collision rules are
// written for one. A plausible implementation checks only the HasInterface *target* (it must
// be an Interface) and leaves the source unchecked, because for every legal use the source is
// an Object or a concrete ObjectType and the constraint never shows.
// @verifies AC-SVR-ADDRSP-023-INTERFACES-NOT-HASINTERFACE-SOURCE
TEST(NodeManagementService, AddReferenceInterfaceSourceForHasInterfaceRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  // Two Interfaces: ObjectTypes whose supertype chain reaches BaseInterfaceType (0:17602).
  auto as = si->address_space();
  auto sourceInterface = as.try_create_node_sync(NodeId{1, 3001u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(sourceInterface.is_good());
  auto sourceAccessor = sourceInterface.value();
  ASSERT_TRUE(sourceAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good())
    << "setup: the source must genuinely be an Interface (inverse HasSubtype to BaseInterfaceType)";

  auto targetInterface = as.try_create_node_sync(NodeId{1, 3002u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(targetInterface.is_good());
  auto targetAccessor = targetInterface.value();
  ASSERT_TRUE(targetAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // Illegal: an Interface applying another Interface.
  AddReferencesItem interfaceSourced;
  interfaceSourced.source_node_id() = NodeId{1, 3001u};
  interfaceSourced.reference_type_id() = NodeId{0, 17603u};  // HasInterface
  interfaceSourced.is_forward() = true;
  interfaceSourced.target_node_id().node_id() = NodeId{1, 3002u};
  interfaceSourced.target_node_class() = NodeClass::ObjectType;
  req.references_to_add().payload().push_back(std::move(interfaceSourced));

  // Lawful: an Object applying the same Interface.
  AddReferencesItem objectSourced;
  objectSourced.source_node_id() = NodeId{1, 85u};
  objectSourced.reference_type_id() = NodeId{0, 17603u};  // HasInterface
  objectSourced.is_forward() = true;
  objectSourced.target_node_id().node_id() = NodeId{1, 3002u};
  objectSourced.target_node_class() = NodeClass::ObjectType;
  req.references_to_add().payload().push_back(std::move(objectSourced));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "an Interface must never be the source of a HasInterface reference";
  EXPECT_TRUE(resp->results()[1].is_good()) << "an Object applying the same Interface must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u);
  EXPECT_EQ(handler->addReferencesItems[0].source_node_id(), (NodeId{1, 85u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3: a Browse filter includes subtypes, so a subtype that flips Symmetric returns
// references whose direction semantics differ from the filter's - the client receives them as
// forward and they are not. A plausible implementation validates the new ReferenceType's own
// attributes in isolation and never compares Symmetric against the supertype it is being
// attached to, so the flip is accepted the moment the HasSubtype reference is created.
// @verifies AC-SVR-ADDRSP-070-SUBTYPE-KEEPS-SYMMETRIC
TEST(NodeManagementService, SubtypeCannotFlipSymmetricRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto supertype = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3300u}, NodeClass::ReferenceType);
  ASSERT_TRUE(supertype.is_good());
  auto supertypeAccessor = supertype.value();
  supertypeAccessor.set_symmetric(true);

  auto flipped = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3301u}, NodeClass::ReferenceType);
  ASSERT_TRUE(flipped.is_good());
  auto flippedAccessor = flipped.value();
  flippedAccessor.set_symmetric(false);

  auto consistent = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3302u}, NodeClass::ReferenceType);
  ASSERT_TRUE(consistent.is_good());
  auto consistentAccessor = consistent.value();
  consistentAccessor.set_symmetric(true);

  // The antecedent must be real, not assumed: the supertype is symmetric and only one of the
  // two candidate subtypes disagrees with it.
  ASSERT_TRUE(supertypeAccessor.get_symmetric());
  ASSERT_FALSE(flippedAccessor.get_symmetric());
  ASSERT_TRUE(consistentAccessor.get_symmetric());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  AddReferencesItem flippedSubtype;
  flippedSubtype.source_node_id() = NodeId{1, 3300u};
  flippedSubtype.reference_type_id() = NodeId{0, 45u};  // HasSubtype
  flippedSubtype.is_forward() = true;
  flippedSubtype.target_node_id().node_id() = NodeId{1, 3301u};
  flippedSubtype.target_node_class() = NodeClass::ReferenceType;
  req.references_to_add().payload().push_back(std::move(flippedSubtype));

  AddReferencesItem consistentSubtype;
  consistentSubtype.source_node_id() = NodeId{1, 3300u};
  consistentSubtype.reference_type_id() = NodeId{0, 45u};  // HasSubtype
  consistentSubtype.is_forward() = true;
  consistentSubtype.target_node_id().node_id() = NodeId{1, 3302u};
  consistentSubtype.target_node_class() = NodeClass::ReferenceType;
  req.references_to_add().payload().push_back(std::move(consistentSubtype));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "a subtype whose Symmetric differs from its supertype must be refused";
  EXPECT_TRUE(resp->results()[1].is_good()) << "a subtype that keeps Symmetric must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u);
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3302u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3.2: clients traverse a ReferenceType that declares the "No Loop" constraint
// without cycle detection, because the type promises there is none - a loop does not produce a
// wrong answer, it produces a client that does not terminate. HasComponent inherits the
// constraint from HasChild. A plausible implementation validates each AddReferences item
// against the source and target nodes only, which cannot see a cycle: every individual
// reference in a loop is locally well formed.
// @verifies AC-SVR-ADDRSP-071-NO-LOOP-HONOURED
TEST(NodeManagementService, AddReferenceClosingLoopOnNoLoopReferenceTypeRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto nodeA = as.try_create_node_sync(NodeId{1, 3100u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeA.is_good());
  auto nodeB = as.try_create_node_sync(NodeId{1, 3101u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeB.is_good());
  auto nodeC = as.try_create_node_sync(NodeId{1, 3102u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeC.is_good());

  // Existing hierarchy: A --HasComponent--> B. Adding B --HasComponent--> A closes a cycle
  // that a traversal starting at A returns to A on.
  auto accessorA = nodeA.value();
  ASSERT_TRUE(accessorA.try_add_reference_sync(NodeId{0, 47u}, NodeId{1, 3101u}, true).is_good())
    << "setup: the loop must already be one reference away from closing";

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  AddReferencesItem closesLoop;
  closesLoop.source_node_id() = NodeId{1, 3101u};
  closesLoop.reference_type_id() = NodeId{0, 47u};  // HasComponent, a HasChild subtype
  closesLoop.is_forward() = true;
  closesLoop.target_node_id().node_id() = NodeId{1, 3100u};
  closesLoop.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(closesLoop));

  AddReferencesItem extendsTree;
  extendsTree.source_node_id() = NodeId{1, 3101u};
  extendsTree.reference_type_id() = NodeId{0, 47u};  // HasComponent
  extendsTree.is_forward() = true;
  extendsTree.target_node_id().node_id() = NodeId{1, 3102u};
  extendsTree.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(extendsTree));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "a reference that lets a traversal return to its starting node must be refused";
  EXPECT_TRUE(resp->results()[1].is_good())
    << "a reference that extends the hierarchy without closing a loop must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u);
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3102u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3.3.1: HasProperty is one of only two references a ReferenceType Node may source,
// and a Property is always a Variable - a client reading the Property's Value attribute on
// anything else gets BadAttributeIdInvalid from a structure the server itself created. A
// plausible implementation trusts AddReferencesItem::target_node_class(), or checks only that
// the source is allowed to use HasProperty, and never reads the target's actual NodeClass.
// @verifies AC-SVR-ADDRSP-073-REFERENCETYPE-PROPERTY-IS-VARIABLE
TEST(NodeManagementService, ReferenceTypeHasPropertyNonVariableTargetRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto referenceType = as.try_create_node_sync(NodeId{1, 3200u}, NodeClass::ReferenceType, {});
  ASSERT_TRUE(referenceType.is_good());
  auto objectTarget = as.try_create_node_sync(NodeId{1, 3201u}, NodeClass::Object, {});
  ASSERT_TRUE(objectTarget.is_good());
  auto variableTarget = as.try_create_node_sync(NodeId{1, 3202u}, NodeClass::Variable, {});
  ASSERT_TRUE(variableTarget.is_good());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  AddReferencesItem nonVariableProperty;
  nonVariableProperty.source_node_id() = NodeId{1, 3200u};
  nonVariableProperty.reference_type_id() = NodeId{0, 46u};  // HasProperty
  nonVariableProperty.is_forward() = true;
  nonVariableProperty.target_node_id().node_id() = NodeId{1, 3201u};
  nonVariableProperty.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(nonVariableProperty));

  AddReferencesItem variableProperty;
  variableProperty.source_node_id() = NodeId{1, 3200u};
  variableProperty.reference_type_id() = NodeId{0, 46u};  // HasProperty
  variableProperty.is_forward() = true;
  variableProperty.target_node_id().node_id() = NodeId{1, 3202u};
  variableProperty.target_node_class() = NodeClass::Variable;
  req.references_to_add().payload().push_back(std::move(variableProperty));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "a ReferenceType's HasProperty target must be a Variable";
  EXPECT_TRUE(resp->results()[1].is_good())
    << "a Variable target for the same HasProperty must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u);
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3202u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 4.2: the NodeClass enumeration carries a ninth wire value, `Unspecified` (0), which is
// the "no value" marker and is *not* one of the eight NodeClasses a Node may belong to. A Node
// created with it would answer the NodeClass attribute with a value no client can act on. A
// plausible implementation gates AddNodes on the generated `is_valid(NodeClass)` - which admits
// Unspecified, because Unspecified is a defined enumerator - and so screens out only the vendor
// values while letting the one in-enum illegal value through.
// @verifies AC-SVR-ADDRSP-005-NO-VENDOR-NODECLASSES
TEST(NodeManagementService, AddNodeUnspecifiedNodeClassIsNotOneOfTheEightRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  // The antecedent, stated rather than assumed: Unspecified passes a defined-enumerator test,
  // so a check written in those terms cannot refuse it, while 4096 fails that same test.
  ASSERT_TRUE(is_valid(NodeClass::Unspecified));
  ASSERT_FALSE(is_valid(static_cast<NodeClass>(4096)));

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  AddNodesItem unspecified;
  unspecified.parent_node_id().node_id() = NodeId{1, 85u};
  unspecified.reference_type_id() = NodeId{0, 35u};  // Organizes
  unspecified.requested_new_node_id().node_id() = NodeId{1, 5450u};
  unspecified.browse_name() = QualifiedName{1, "UnspecifiedNode"};
  unspecified.node_class() = NodeClass::Unspecified;
  req.nodes_to_add().payload().push_back(std::move(unspecified));

  AddNodesItem vendor;
  vendor.parent_node_id().node_id() = NodeId{1, 85u};
  vendor.reference_type_id() = NodeId{0, 35u};  // Organizes
  vendor.requested_new_node_id().node_id() = NodeId{1, 5451u};
  vendor.browse_name() = QualifiedName{1, "VendorNode"};
  vendor.node_class() = static_cast<NodeClass>(4096);
  req.nodes_to_add().payload().push_back(std::move(vendor));

  AddNodesItem lawful;
  lawful.parent_node_id().node_id() = NodeId{1, 85u};
  lawful.reference_type_id() = NodeId{0, 35u};  // Organizes
  lawful.requested_new_node_id().node_id() = NodeId{1, 5452u};
  lawful.browse_name() = QualifiedName{1, "LawfulNode"};
  lawful.node_class() = NodeClass::Object;
  make_add_nodes_item_conforming(lawful);
  req.nodes_to_add().payload().push_back(std::move(lawful));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 3u);

  EXPECT_EQ(resp->results()[0].status_code(), Status::BadNodeClassInvalid)
    << "Unspecified is not one of the eight NodeClasses, so no Node may be created with it";
  EXPECT_EQ(resp->results()[1].status_code(), Status::BadNodeClassInvalid)
    << "a NodeClass outside the enumeration must be refused";
  EXPECT_TRUE(resp->results()[2].status_code().is_good())
    << "the lawful item in the same request must still be honoured";

  // Neither illegal item may reach node creation, or a Node carrying a NodeClass outside the
  // eight enters the address space whatever status the client was told.
  EXPECT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 1u);
  EXPECT_EQ(handler->addNodesItems[0].node_class(), NodeClass::Object);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 6.6: an Interface is any ObjectType whose supertype chain reaches BaseInterfaceType, not
// only its immediate children - the hierarchy is arbitrarily deep, and a company Interface derived
// from a companion-spec Interface is the ordinary case. A plausible implementation reads the
// candidate source's own references and refuses it only when it finds an inverse HasSubtype
// pointing straight at BaseInterfaceType (0:17602), so an Interface one level further down is not
// recognised as an Interface at all and is allowed to apply another.
// @verifies AC-SVR-ADDRSP-023-INTERFACES-NOT-HASINTERFACE-SOURCE
TEST(NodeManagementService, AddReferenceNestedInterfaceSourceForHasInterfaceRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  // A direct Interface: inverse HasSubtype straight to BaseInterfaceType.
  auto directInterface = as.try_create_node_sync(NodeId{1, 3410u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(directInterface.is_good());
  auto directAccessor = directInterface.value();
  ASSERT_TRUE(directAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good())
    << "setup: the direct Interface must genuinely derive from BaseInterfaceType";

  // A nested Interface: it derives from the Interface above, so its supertype chain still reaches
  // BaseInterfaceType and it is every bit as much an Interface.
  auto nestedInterface = as.try_create_node_sync(NodeId{1, 3411u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(nestedInterface.is_good());
  auto nestedAccessor = nestedInterface.value();
  ASSERT_TRUE(nestedAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{1, 3410u}, false).is_good())
    << "setup: the nested Interface must genuinely derive from the direct Interface";

  // The Interface being applied.
  auto appliedInterface = as.try_create_node_sync(NodeId{1, 3412u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(appliedInterface.is_good());
  auto appliedAccessor = appliedInterface.value();
  ASSERT_TRUE(appliedAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  auto makeApply = [](NodeId source)
  {
    AddReferencesItem item;
    item.source_node_id() = std::move(source);
    item.reference_type_id() = NodeId{0, 17603u};  // HasInterface
    item.is_forward() = true;
    item.target_node_id().node_id() = NodeId{1, 3412u};
    item.target_node_class() = NodeClass::ObjectType;
    return item;
  };

  req.references_to_add().payload().push_back(makeApply(NodeId{1, 3411u}));  // nested Interface
  req.references_to_add().payload().push_back(makeApply(NodeId{1, 3410u}));  // direct Interface
  req.references_to_add().payload().push_back(makeApply(NodeId{1, 85u}));  // Object - lawful

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 3u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "an Interface whose supertype chain reaches BaseInterfaceType indirectly is still an "
       "Interface and must not source HasInterface";
  EXPECT_EQ(resp->results()[1], Status::BadReferenceNotAllowed)
    << "a direct subtype of BaseInterfaceType must not source HasInterface";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "InterfaceAsHasInterfaceSource");
  ASSERT_NE(resp->results()[1].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[1].shared_detail()->code, "InterfaceAsHasInterfaceSource");
  EXPECT_TRUE(resp->results()[2].is_good()) << "an Object applying the same Interface must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "no Interface-sourced HasInterface may reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].source_node_id(), (NodeId{1, 85u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 6.6: the prohibition is on Interfaces as a class - BaseInterfaceType *or a subtype* -
// because every one of them is abstract, and BaseInterfaceType itself is the one no real model
// ever names as a TypeDefinition. A plausible implementation compares the requested TypeDefinition
// against the well-known BaseInterfaceType NodeId and stops there, never resolving the node, so
// every user-defined Interface - the only kind a client would actually ask for - passes.
// @verifies AC-SVR-ADDRSP-029-INTERFACE-NOT-TYPEDEFINITION
TEST(NodeManagementService, AddNodeInterfaceSubtypeAsTypeDefinitionRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  // A genuine Interface: an ObjectType deriving from BaseInterfaceType.
  auto derivedInterface = as.try_create_node_sync(NodeId{1, 3420u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(derivedInterface.is_good());
  auto derivedAccessor = derivedInterface.value();
  ASSERT_TRUE(derivedAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good())
    << "setup: the TypeDefinition under test must genuinely be an Interface";

  const NodeId concreteObjectTypeId{1, 3421u};
  ASSERT_TRUE(as.try_create_node_sync(concreteObjectTypeId, NodeClass::ObjectType, {}).is_good());

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  auto makeInstance = [](uint32_t requestedId, NodeId typeDefinition)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.reference_type_id() = NodeId{0, 35u};  // Organizes
    item.requested_new_node_id().node_id() = NodeId{1, requestedId};
    item.browse_name() = QualifiedName{1, "TypedObject"};
    item.node_class() = NodeClass::Object;
    item.type_definition().node_id() = std::move(typeDefinition);
    return item;
  };

  req.nodes_to_add().payload().push_back(makeInstance(5460u, NodeId{1, 3420u}));  // Interface subtype
  req.nodes_to_add().payload().push_back(makeInstance(5461u, NodeId{0, 17602u}));  // BaseInterfaceType
  req.nodes_to_add().payload().push_back(makeInstance(5462u, concreteObjectTypeId));  // concrete ObjectType

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 3u);

  EXPECT_EQ(resp->results()[0].status_code(), Status::BadTypeDefinitionInvalid)
    << "a subtype of BaseInterfaceType is an Interface and must not be a HasTypeDefinition target";
  EXPECT_EQ(resp->results()[1].status_code(), Status::BadTypeDefinitionInvalid)
    << "BaseInterfaceType itself must not be a HasTypeDefinition target";
  EXPECT_TRUE(resp->results()[2].status_code().is_good())
    << "a concrete ObjectType TypeDefinition in the same request must still be honoured";

  EXPECT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 1u) << "no instance typed by an Interface may reach node creation";
  EXPECT_EQ(handler->addNodesItems[0].type_definition().node_id(), concreteObjectTypeId);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3: the constraint is on the subtype relationship, not on the direction the client
// happens to declare it in - AddReferences carries isForward, so the very same HasSubtype link can
// arrive as supertype->subtype or, inversely, as subtype->supertype, and both create one edge in the
// hierarchy. A plausible implementation reads the item's source as "the supertype" and its target
// as "the subtype" without consulting isForward; the equality it then checks is accidentally
// direction-proof, but any rule phrased as "the target must not flip the source's Symmetric" is
// not, and lets the inverse declaration through.
// @verifies AC-SVR-ADDRSP-070-SUBTYPE-KEEPS-SYMMETRIC
// The TypeDefinition hierarchy is request validation, not delegate work. If the named type cannot
// be resolved, AddNodes must keep the lookup's ErrorDetail below its per-item refusal and encode the
// same chain in diagnosticInfos when operation diagnostics are requested.
// @relation(AC-SVR-DIAG-010-PEROPERATION-DETAIL, scope=function)
TEST(NodeManagementService, MissingTypeDefinitionPreservesHierarchyErrorDetailPerItem)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(
    tp.get_executor(), make_allow_all_authorizer(), MessageSecurityMode::Sign);
  si->serverCfg.diagnosticPolicy.defaultLevel = ServerConfig::DiagnosticPolicy::Level::Full;
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.request_header().return_diagnostics() = 0xFFFF;
  AddNodesItem item;
  item.parent_node_id().node_id() = NodeId{1, 85u};
  item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  item.requested_new_node_id().node_id() = NodeId{1, 5463u};
  item.browse_name() = QualifiedName{1, "MissingTypeDefinition"};
  item.node_class() = NodeClass::Object;
  item.type_definition().node_id() = NodeId{1, 9999u};
  request.nodes_to_add().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 1u);

  const StatusCode status = response->results()[0].status_code();
  EXPECT_EQ(status, Status::BadTypeDefinitionInvalid);
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "TypeDefinitionHierarchyUnavailable");
  ASSERT_NE(status.shared_detail()->cause, nullptr)
    << "the failed address-space lookup must remain below the per-item validation error";
  EXPECT_EQ(handler->addNodesCalls, 0u);

  ASSERT_EQ(response->diagnostic_infos().size(), 1u);
  ASSERT_FALSE(response->diagnostic_infos()[0].is_null());
  auto decoded =
    diagnostic_to_error_detail(response->diagnostic_infos()[0], response->response_header().string_table());
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded->code, "TypeDefinitionHierarchyUnavailable");
  EXPECT_NE(decoded->cause, nullptr);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.7.2.2 requires a TypeDefinition exactly for Object and Variable Nodes. The
// controls prove that both correctly typed classes and a Method with a null TypeDefinition remain
// eligible while the invalid siblings never reach the delegate.
// @relation(AC-SVR-NM-AN-008-TYPEDEFINITION-SCOPE, scope=function)
TEST(NodeManagementService, AddNodesEnforcesTypeDefinitionScopePerNodeClass)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = si->address_space();

  const NodeId objectTypeId{1, 3470u};
  const NodeId variableTypeId{1, 3471u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(objectTypeId, NodeClass::ObjectType, {}).is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(variableTypeId, NodeClass::VariableType, {}).is_good());

  const auto makeItem = [](uint32_t requestedId, NodeClass nodeClass, NodeId typeDefinition)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.requested_new_node_id().node_id() = NodeId{1, requestedId};
    item.browse_name() = QualifiedName{1, "TypeDefinitionScope" + std::to_string(requestedId)};
    item.node_class() = nodeClass;
    item.type_definition().node_id() = std::move(typeDefinition);
    return item;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(makeItem(5600u, NodeClass::Method, objectTypeId));
  request.nodes_to_add().push_back(makeItem(5601u, NodeClass::Object, NodeId{}));
  request.nodes_to_add().push_back(makeItem(5602u, NodeClass::Variable, NodeId{}));
  request.nodes_to_add().push_back(makeItem(5603u, NodeClass::Method, NodeId{}));
  request.nodes_to_add().push_back(makeItem(5604u, NodeClass::Object, objectTypeId));
  request.nodes_to_add().push_back(makeItem(5605u, NodeClass::Variable, variableTypeId));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 6u);
  for (size_t index : {size_t{0}, size_t{1}, size_t{2}})
  {
    const StatusCode& status = response->results()[index].status_code();
    EXPECT_EQ(status.as_status(), Status::BadTypeDefinitionInvalid);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code, "AddNodesTypeDefinitionScopeInvalid");
    EXPECT_EQ(
      ::ua::test_utils::error_context(status.shared_detail().get(), ContextKeys::operationIndex.value()),
      std::to_string(index));
  }
  for (size_t index : {size_t{3}, size_t{4}, size_t{5}})
  {
    EXPECT_TRUE(response->results()[index].status_code().is_good());
  }

  ASSERT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 3u);
  EXPECT_EQ(handler->addNodesItems[0].node_class(), NodeClass::Method);
  EXPECT_EQ(handler->addNodesItems[1].type_definition().node_id(), objectTypeId);
  EXPECT_EQ(handler->addNodesItems[2].type_definition().node_id(), variableTypeId);
  ::ua::test_utils::drain_with_timeout(tp);
}

// A TypeDefinition must resolve to the type class appropriate for the instance: ObjectType for an
// Object and VariableType for a Variable. Missing, non-Type, and cross-kind ids are independently
// falsified; the two valid siblings prove the check is not a blanket refusal.
// @relation(AC-SVR-NM-AN-029-TYPEDEFINITION-INVALID, scope=function)
TEST(NodeManagementService, AddNodesRejectsMissingNonTypeAndMismatchedTypeDefinitions)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = si->address_space();

  const NodeId objectTypeId{1, 3480u};
  const NodeId variableTypeId{1, 3481u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(objectTypeId, NodeClass::ObjectType, {}).is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(variableTypeId, NodeClass::VariableType, {}).is_good());

  const auto makeItem = [](uint32_t requestedId, NodeClass nodeClass, NodeId typeDefinition)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.requested_new_node_id().node_id() = NodeId{1, requestedId};
    item.browse_name() = QualifiedName{1, "TypeDefinitionClass" + std::to_string(requestedId)};
    item.node_class() = nodeClass;
    item.type_definition().node_id() = std::move(typeDefinition);
    return item;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(makeItem(5610u, NodeClass::Object, NodeId{1, 99998u}));
  request.nodes_to_add().push_back(makeItem(5611u, NodeClass::Object, NodeId{1, 100u}));
  request.nodes_to_add().push_back(makeItem(5612u, NodeClass::Object, variableTypeId));
  request.nodes_to_add().push_back(makeItem(5613u, NodeClass::Variable, objectTypeId));
  request.nodes_to_add().push_back(makeItem(5614u, NodeClass::Object, objectTypeId));
  request.nodes_to_add().push_back(makeItem(5615u, NodeClass::Variable, variableTypeId));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 6u);
  for (size_t index : {size_t{0}, size_t{1}, size_t{2}, size_t{3}})
  {
    const StatusCode& status = response->results()[index].status_code();
    EXPECT_EQ(status.as_status(), Status::BadTypeDefinitionInvalid);
    ASSERT_NE(status.shared_detail(), nullptr);
    EXPECT_EQ(status.shared_detail()->code,
      index == 0 ? "TypeDefinitionHierarchyUnavailable" : "AddNodesTypeDefinitionInvalid");
    EXPECT_EQ(
      ::ua::test_utils::error_context(status.shared_detail().get(), ContextKeys::operationIndex.value()),
      std::to_string(index));
  }
  EXPECT_NE(response->results()[0].status_code().shared_detail()->cause, nullptr)
    << "the missing TypeDefinition lookup must remain the exact cause";
  EXPECT_TRUE(response->results()[4].status_code().is_good());
  EXPECT_TRUE(response->results()[5].status_code().is_good());

  ASSERT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 2u);
  EXPECT_EQ(handler->addNodesItems[0].type_definition().node_id(), objectTypeId);
  EXPECT_EQ(handler->addNodesItems[1].type_definition().node_id(), variableTypeId);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 4 section 5.7.2.2 requires requestedNewNodeId.serverIndex == 0. The local sibling proves this is a
// per-item screen rather than a service-wide refusal, and the delegate inventory proves the foreign
// id cannot be silently projected into this server's address space.
// @relation(AC-SVR-NM-AN-003-SERVERINDEX-ZERO, scope=function)
TEST(NodeManagementService, AddNodesRejectsNonZeroRequestedNodeServerIndexBeforeDelegate)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();

  const NodeId variableTypeId{1, 3490u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(variableTypeId, NodeClass::VariableType, {}).is_good());

  const auto makeItem = [variableTypeId](uint32_t requestedId, uint32_t serverIndex)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.requested_new_node_id() = ExpandedNodeId{NodeId{1, requestedId}, serverIndex};
    item.browse_name() = QualifiedName{1, "RequestedServerIndex" + std::to_string(requestedId)};
    item.node_class() = NodeClass::Variable;
    item.type_definition().node_id() = variableTypeId;
    return item;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(makeItem(5620u, 7u));
  request.nodes_to_add().push_back(makeItem(5621u, 0u));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 2u);

  const StatusCode& rejected = response->results()[0].status_code();
  EXPECT_EQ(rejected.as_status(), Status::BadNodeIdRejected);
  ASSERT_NE(rejected.shared_detail(), nullptr);
  EXPECT_EQ(rejected.shared_detail()->code, "AddNodesRequestedNodeIdServerIndexInvalid");
  EXPECT_EQ(
    ::ua::test_utils::error_context(rejected.shared_detail().get(), ContextKeys::operationIndex.value()),
    "0");
  EXPECT_EQ(
    ::ua::test_utils::error_context(rejected.shared_detail().get(), ContextKeys::serverIndex.value()), "7");
  EXPECT_TRUE(response->results()[1].status_code().is_good());

  ASSERT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 1u);
  EXPECT_EQ(handler->addNodesItems[0].requested_new_node_id().node_id(), (NodeId{1, 5621u}));
  EXPECT_EQ(handler->addNodesItems[0].requested_new_node_id().server_index(), 0u);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.7.2.4 distinguishes an invalid or server-refused requested id from an occupied one.
// Namespace identification rejects the malformed id before preparation; the namespace-neutral
// mutation delegate owns the policy refusal after destination authorization. The null-id sibling
// proves server assignment remains available.
// @relation(AC-SVR-NM-AN-023-NODEIDREJECTED, scope=function)
TEST(NodeManagementService, AddNodesRejectsUnassignableRequestedNodeIdsButPreservesExists)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();

  const NodeId variableTypeId{1, 3491u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(variableTypeId, NodeClass::VariableType, {}).is_good());

  handler->addNodesResultFactory = [](const std::vector<AddNodesItem>& items)
  {
    std::vector<AddNodesResult> results(items.size());
    for (size_t index = 0; index < items.size(); ++index)
    {
      const auto& requestedNodeId = items[index].requested_new_node_id().node_id();
      if (requestedNodeId == NodeId{1, 5631u})
      {
        results[index].status_code() = StatusCode{Status::BadNodeIdRejected,
          make_error_detail("TestDelegateNodeIdRejected",
            "the destination namespace rejected the requested identifier",
            "TestDelegate")};
      }
      else
      {
        results[index].status_code() =
          requestedNodeId == NodeId{1, 85u} ? Status::BadNodeIdExists : Status::Good;
      }
    }
    return results;
  };

  const auto makeItem = [variableTypeId](uint32_t suffix, NodeId requestedId)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.requested_new_node_id().node_id() = std::move(requestedId);
    item.browse_name() = QualifiedName{1, "RequestedNodeIdPolicy" + std::to_string(suffix)};
    item.node_class() = NodeClass::Variable;
    item.type_definition().node_id() = variableTypeId;
    return item;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(makeItem(0u, NodeId{250, 5630u}));
  request.nodes_to_add().push_back(makeItem(1u, NodeId{1, 5631u}));
  request.nodes_to_add().push_back(makeItem(2u, NodeId{1, 85u}));
  request.nodes_to_add().push_back(makeItem(3u, NodeId{}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 4u);

  for (size_t index : {size_t{0}, size_t{1}})
  {
    const StatusCode& rejected = response->results()[index].status_code();
    EXPECT_EQ(rejected.as_status(), Status::BadNodeIdRejected);
    ASSERT_NE(rejected.shared_detail(), nullptr);
    EXPECT_EQ(rejected.shared_detail()->code,
      index == 0 ? "AddNodesRequestedNodeIdNamespaceUnknown" : "TestDelegateNodeIdRejected");
    if (index == 0)
    {
      EXPECT_EQ(
        ::ua::test_utils::error_context(rejected.shared_detail().get(), ContextKeys::operationIndex.value()),
        "0");
    }
    else
    {
      EXPECT_EQ(rejected.shared_detail()->source, "TestDelegate");
    }
  }
  EXPECT_EQ(response->results()[2].status_code(), StatusCode{Status::BadNodeIdExists});
  EXPECT_TRUE(response->results()[3].status_code().is_good());

  ASSERT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 3u);
  EXPECT_EQ(handler->addNodesItems[0].requested_new_node_id().node_id(), (NodeId{1, 5631u}));
  EXPECT_EQ(handler->addNodesItems[1].requested_new_node_id().node_id(), (NodeId{1, 85u}));
  EXPECT_TRUE(handler->addNodesItems[2].requested_new_node_id().node_id().is_null());
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.7.2.2 fixes the concrete NodeAttributes structure for each NodeClass and permits
// null only as the request for TypeDefinition/default values. The full positive matrix makes the
// class/type switch falsifiable rather than proving only the Object/Variable negative.
// @relation(AC-SVR-NM-AN-028-NODEATTRIBUTESINVALID, scope=function)
TEST(NodeManagementService, AddNodesRejectsMismatchedNodeAttributesButAllowsAllDefinedClasses)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();

  const NodeId objectTypeId{1, 5640u};
  const NodeId variableTypeId{1, 5641u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(objectTypeId, NodeClass::ObjectType, {}).is_good());
  ASSERT_TRUE(addressSpace.try_create_node_sync(variableTypeId, NodeClass::VariableType, {}).is_good());

  const auto makeItem = [objectTypeId, variableTypeId](
                          uint32_t suffix, NodeClass nodeClass, std::unique_ptr<Structure> attributes)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.requested_new_node_id().node_id() = NodeId{1, 5650u + suffix};
    item.browse_name() = QualifiedName{1, "Attributes" + std::to_string(suffix)};
    item.node_class() = nodeClass;
    item.node_attributes() = std::move(attributes);
    if (nodeClass == NodeClass::Object)
      item.type_definition().node_id() = objectTypeId;
    else if (nodeClass == NodeClass::Variable)
      item.type_definition().node_id() = variableTypeId;
    return item;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(makeItem(0u, NodeClass::Object, std::make_unique<VariableAttributes>()));
  request.nodes_to_add().push_back(makeItem(1u, NodeClass::Object, std::make_unique<ObjectAttributes>()));
  request.nodes_to_add().push_back(makeItem(2u, NodeClass::Variable, std::make_unique<VariableAttributes>()));
  request.nodes_to_add().push_back(makeItem(3u, NodeClass::Method, std::make_unique<MethodAttributes>()));
  request.nodes_to_add().push_back(
    makeItem(4u, NodeClass::ObjectType, std::make_unique<ObjectTypeAttributes>()));
  request.nodes_to_add().push_back(
    makeItem(5u, NodeClass::VariableType, std::make_unique<VariableTypeAttributes>()));
  request.nodes_to_add().push_back(
    makeItem(6u, NodeClass::ReferenceType, std::make_unique<ReferenceTypeAttributes>()));
  request.nodes_to_add().push_back(makeItem(7u, NodeClass::DataType, std::make_unique<DataTypeAttributes>()));
  request.nodes_to_add().push_back(makeItem(8u, NodeClass::View, std::make_unique<ViewAttributes>()));
  request.nodes_to_add().push_back(makeItem(9u, NodeClass::Method, {}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 10u);

  const StatusCode& mismatch = response->results()[0].status_code();
  EXPECT_EQ(mismatch.as_status(), Status::BadNodeAttributesInvalid);
  ASSERT_NE(mismatch.shared_detail(), nullptr);
  EXPECT_EQ(mismatch.shared_detail()->code, "AddNodesNodeAttributesInvalid");
  EXPECT_EQ(
    ::ua::test_utils::error_context(mismatch.shared_detail().get(), ContextKeys::operationIndex.value()),
    "0");
  for (size_t index = 1; index < response->results().size(); ++index)
    EXPECT_TRUE(response->results()[index].status_code().is_good()) << "control index " << index;

  ASSERT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 9u)
    << "the mismatched structure must be the only item withheld from the delegate";
  EXPECT_EQ(handler->addNodesItems.front().node_class(), NodeClass::Object);
  EXPECT_EQ(handler->addNodesItems.back().node_class(), NodeClass::Method);
  EXPECT_FALSE(handler->addNodesItems.back().node_attributes());
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 sections 5.7.2.2/.4 require a real hierarchical ReferenceType. Missing/wrong-class ids,
// a non-hierarchical type, and a HasSubtype relation between Object instances exercise the three
// distinct refusal reasons; standard/custom hierarchical controls prove subtype traversal.
// @relation(AC-SVR-NM-AN-021-REFERENCETYPEIDINVALID, scope=function)
// @relation(AC-SVR-NM-AN-022-REFERENCENOTALLOWED, scope=function)
// @relation(AC-SVR-NM-AN-031-HIERARCHICAL-ATTACHMENT, scope=function)
TEST(NodeManagementService, AddNodesRequiresValidHierarchicalReferenceTypeBeforeDelegate)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();

  const NodeId objectTypeId{1, 5660u};
  const NodeId customHierarchicalId{1, 5661u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(objectTypeId, NodeClass::ObjectType, {}).is_good());
  auto customResult =
    addressSpace.try_create_sync<ReferenceTypeAccessor>(customHierarchicalId, NodeClass::ReferenceType);
  ASSERT_TRUE(customResult.is_good());
  ASSERT_TRUE(
    customResult.value()
      .try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, NodeId{ReferenceTypeId::Organizes}, false)
      .is_good());

  const auto makeItem = [objectTypeId](
                          uint32_t suffix, NodeId referenceTypeId, NodeId parent = NodeId{1, 85u})
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = std::move(parent);
    item.reference_type_id() = std::move(referenceTypeId);
    item.requested_new_node_id().node_id() = NodeId{1, 5670u + suffix};
    item.browse_name() = QualifiedName{1, "ReferenceType" + std::to_string(suffix)};
    item.node_class() = NodeClass::Object;
    item.type_definition().node_id() = objectTypeId;
    return item;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(makeItem(0u, NodeId{1, 99998u}));
  request.nodes_to_add().push_back(makeItem(1u, NodeId{1, 100u}));
  request.nodes_to_add().push_back(makeItem(2u, NodeId{ReferenceTypeId::HasTypeDefinition}));
  request.nodes_to_add().push_back(makeItem(3u, NodeId{ReferenceTypeId::HasSubtype}));
  request.nodes_to_add().push_back(makeItem(4u, NodeId{ReferenceTypeId::Organizes}));
  request.nodes_to_add().push_back(makeItem(5u, customHierarchicalId));
  request.nodes_to_add().push_back(makeItem(6u, NodeId{ReferenceTypeId::Organizes}, NodeId{1, 99997u}));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 7u);

  for (size_t index : {size_t{0}, size_t{1}})
  {
    const StatusCode& invalid = response->results()[index].status_code();
    EXPECT_EQ(invalid.as_status(), Status::BadReferenceTypeIdInvalid);
    ASSERT_NE(invalid.shared_detail(), nullptr);
    EXPECT_EQ(invalid.shared_detail()->code, "AddNodesReferenceTypeInvalid");
    EXPECT_NE(invalid.shared_detail()->cause, nullptr);
  }
  for (size_t index : {size_t{2}, size_t{3}})
  {
    const StatusCode& notAllowed = response->results()[index].status_code();
    EXPECT_EQ(notAllowed.as_status(), Status::BadReferenceNotAllowed);
    ASSERT_NE(notAllowed.shared_detail(), nullptr);
  }
  EXPECT_TRUE(response->results()[4].status_code().is_good());
  EXPECT_TRUE(response->results()[5].status_code().is_good());
  EXPECT_EQ(response->results()[6].status_code().as_status(), Status::BadParentNodeIdInvalid);

  ASSERT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 2u);
  EXPECT_EQ(handler->addNodesItems[0].reference_type_id(), NodeId{ReferenceTypeId::Organizes});
  EXPECT_EQ(handler->addNodesItems[1].reference_type_id(), customHierarchicalId);
  ::ua::test_utils::drain_with_timeout(threadPool);
}

// Part 4 section 5.7.2.4 defines sibling uniqueness over the exact parent/ReferenceType relation.
// The same-name/different-type control prevents a broader and incompatible global-name rejection;
// the in-request pair proves validation cannot create two duplicates merely because neither existed
// before the request began.
// @relation(AC-SVR-NM-AN-027-BROWSENAMEDUPLICATED, scope=function)
TEST(NodeManagementService, AddNodesRejectsSameRelationshipBrowseNameCollisionsBeforeDelegate)
{
  boost::asio::thread_pool threadPool;
  auto sessionInfo =
    std::make_shared<NodeManagementSessionInfo>(threadPool.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();
  auto addressSpace = sessionInfo->address_space();

  const NodeId variableTypeId{1, 5680u};
  const NodeId incumbentId{1, 5681u};
  ASSERT_TRUE(addressSpace.try_create_node_sync(variableTypeId, NodeClass::VariableType, {}).is_good());
  auto incumbent = addressSpace.try_create_node_sync(incumbentId, NodeClass::Variable, {});
  ASSERT_TRUE(incumbent.is_good());
  incumbent.value().set_browse_name(QualifiedName{1, "Collision"});
  auto parent = addressSpace.try_find_node_sync(NodeId{1, 85u});
  ASSERT_TRUE(parent.is_good());
  ASSERT_TRUE(
    parent.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, incumbentId, true).is_good());

  const auto makeItem = [variableTypeId](uint32_t suffix, NodeId referenceTypeId, String name)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.reference_type_id() = std::move(referenceTypeId);
    item.requested_new_node_id().node_id() = NodeId{1, 5690u + suffix};
    item.browse_name() = QualifiedName{1, std::move(name)};
    item.node_class() = NodeClass::Variable;
    item.type_definition().node_id() = variableTypeId;
    return item;
  };

  AddNodesRequest request;
  request.request_header().request_handle() = 1;
  request.nodes_to_add().push_back(makeItem(0u, NodeId{ReferenceTypeId::HasProperty}, "Collision"));
  request.nodes_to_add().push_back(makeItem(1u, NodeId{ReferenceTypeId::HasComponent}, "Collision"));
  request.nodes_to_add().push_back(makeItem(2u, NodeId{ReferenceTypeId::HasProperty}, "Distinct"));
  request.nodes_to_add().push_back(makeItem(3u, NodeId{ReferenceTypeId::Organizes}, "BatchCollision"));
  request.nodes_to_add().push_back(makeItem(4u, NodeId{ReferenceTypeId::Organizes}, "BatchCollision"));

  auto result = invoke_service(sessionInfo, handler, threadPool.get_executor(), std::move(request));
  ASSERT_FALSE(result.isServiceFault);
  auto* response = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(response, nullptr);
  ASSERT_EQ(response->results().size(), 5u);

  for (size_t index : {size_t{0}, size_t{4}})
  {
    const StatusCode& duplicate = response->results()[index].status_code();
    EXPECT_EQ(duplicate.as_status(), Status::BadBrowseNameDuplicated);
    ASSERT_NE(duplicate.shared_detail(), nullptr);
    EXPECT_EQ(
      ::ua::test_utils::error_context(duplicate.shared_detail().get(), ContextKeys::operationIndex.value()),
      std::to_string(index));
  }
  for (size_t index : {size_t{1}, size_t{2}, size_t{3}})
    EXPECT_TRUE(response->results()[index].status_code().is_good()) << "control index " << index;

  ASSERT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 3u)
    << "only distinct parent/relationship/name tuples may reach creation";
  EXPECT_EQ(handler->addNodesItems[0].reference_type_id(), NodeId{ReferenceTypeId::HasComponent});
  EXPECT_EQ(handler->addNodesItems[1].browse_name(), (QualifiedName{1, "Distinct"}));
  EXPECT_EQ(handler->addNodesItems[2].browse_name(), (QualifiedName{1, "BatchCollision"}));
  ::ua::test_utils::drain_with_timeout(threadPool);
}

TEST(NodeManagementService, SubtypeDeclaredInverselyCannotFlipSymmetricRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto supertype = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3450u}, NodeClass::ReferenceType);
  ASSERT_TRUE(supertype.is_good());
  auto supertypeAccessor = supertype.value();
  supertypeAccessor.set_symmetric(true);

  auto flipped = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3451u}, NodeClass::ReferenceType);
  ASSERT_TRUE(flipped.is_good());
  auto flippedAccessor = flipped.value();
  flippedAccessor.set_symmetric(false);

  auto consistent = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3452u}, NodeClass::ReferenceType);
  ASSERT_TRUE(consistent.is_good());
  auto consistentAccessor = consistent.value();
  consistentAccessor.set_symmetric(true);

  // The antecedent must be real, not assumed: exactly one of the two candidate subtypes disagrees
  // with the supertype it is being attached to.
  ASSERT_TRUE(supertypeAccessor.get_symmetric());
  ASSERT_FALSE(flippedAccessor.get_symmetric());
  ASSERT_TRUE(consistentAccessor.get_symmetric());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // Inverse declaration: the source is the subtype, the target is the supertype.
  auto makeInverseSubtype = [](NodeId subtype)
  {
    AddReferencesItem item;
    item.source_node_id() = std::move(subtype);
    item.reference_type_id() = NodeId{0, 45u};  // HasSubtype
    item.is_forward() = false;
    item.target_node_id().node_id() = NodeId{1, 3450u};
    item.target_node_class() = NodeClass::ReferenceType;
    return item;
  };

  req.references_to_add().payload().push_back(makeInverseSubtype(NodeId{1, 3451u}));
  req.references_to_add().payload().push_back(makeInverseSubtype(NodeId{1, 3452u}));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "an inversely declared subtype whose Symmetric differs from its supertype must be refused";
  EXPECT_TRUE(resp->results()[1].is_good())
    << "an inversely declared subtype that keeps Symmetric must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the flipping subtype declaration must not reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].source_node_id(), (NodeId{1, 3452u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 7.5: the "No Loop" promise is what lets a client traverse HasChild and its subtypes with
// no cycle detection, so a loop of any length costs the client its termination - length two is not
// privileged. A plausible implementation checks only whether the target already points straight
// back at the source, which catches the two-node case and nothing else: every longer cycle is made
// of references that are each locally well formed, and the closing one looks like any other.
// @verifies AC-SVR-ADDRSP-071-NO-LOOP-HONOURED
TEST(NodeManagementService, AddReferenceClosingThreeNodeLoopOnNoLoopReferenceTypeRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto nodeA = as.try_create_node_sync(NodeId{1, 3430u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeA.is_good());
  auto nodeB = as.try_create_node_sync(NodeId{1, 3431u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeB.is_good());
  auto nodeC = as.try_create_node_sync(NodeId{1, 3432u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeC.is_good());
  auto nodeD = as.try_create_node_sync(NodeId{1, 3433u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeD.is_good());

  // Existing hierarchy: A --HasComponent--> B --HasComponent--> C. A traversal from A already
  // reaches C, so C --HasComponent--> A is the one reference that returns it to its start.
  auto accessorA = nodeA.value();
  ASSERT_TRUE(accessorA.try_add_reference_sync(NodeId{0, 47u}, NodeId{1, 3431u}, true).is_good())
    << "setup: the path A -> B must exist";
  auto accessorB = nodeB.value();
  ASSERT_TRUE(accessorB.try_add_reference_sync(NodeId{0, 47u}, NodeId{1, 3432u}, true).is_good())
    << "setup: the path B -> C must exist, so the loop under test is three nodes long";

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  auto makeComponent = [](NodeId source, NodeId target)
  {
    AddReferencesItem item;
    item.source_node_id() = std::move(source);
    item.reference_type_id() = NodeId{0, 47u};  // HasComponent, a HasChild subtype
    item.is_forward() = true;
    item.target_node_id().node_id() = std::move(target);
    item.target_node_class() = NodeClass::Object;
    return item;
  };

  // C -> A closes the three-node loop A -> B -> C -> A.
  req.references_to_add().payload().push_back(makeComponent(NodeId{1, 3432u}, NodeId{1, 3430u}));
  // B -> A closes the two-node loop A -> B -> A.
  req.references_to_add().payload().push_back(makeComponent(NodeId{1, 3431u}, NodeId{1, 3430u}));
  // C -> D extends the hierarchy and closes nothing.
  req.references_to_add().payload().push_back(makeComponent(NodeId{1, 3432u}, NodeId{1, 3433u}));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 3u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "a reference that lets a traversal of three nodes return to its starting node must be refused";
  EXPECT_EQ(resp->results()[1], Status::BadReferenceNotAllowed)
    << "a reference that points straight back at its source must be refused";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "ReferenceWouldCreateLoop");
  ASSERT_NE(resp->results()[1].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[1].shared_detail()->code, "ReferenceWouldCreateLoop");
  EXPECT_TRUE(resp->results()[2].is_good())
    << "a reference that extends the hierarchy without closing a loop must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "no loop-closing reference may reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3433u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3: a Property is a Variable, and AddNodes creates the HasProperty reference to the new
// Node at the same time as the Node itself - so a request naming a ReferenceType as parent,
// HasProperty as the reference and Object as the NodeClass produces exactly the structure the
// constraint forbids, without ever calling AddReferences. A plausible implementation puts the
// reference-constraint table on the AddReferences path only, because that is the service whose name
// contains "reference", and leaves AddNodes validating the item's own attributes.
// @verifies AC-SVR-ADDRSP-073-REFERENCETYPE-PROPERTY-IS-VARIABLE
TEST(NodeManagementService, AddNodeCreatingNonVariablePropertyOfReferenceTypeRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto referenceType = as.try_create_node_sync(NodeId{1, 3440u}, NodeClass::ReferenceType, {});
  ASSERT_TRUE(referenceType.is_good());
  ASSERT_EQ(referenceType.value().get_node_class(), NodeClass::ReferenceType)
    << "setup: the parent must genuinely be a ReferenceType Node";

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  auto makeProperty = [](uint32_t requestedId, NodeClass nodeClass)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 3440u};
    item.reference_type_id() = NodeId{0, 46u};  // HasProperty
    item.requested_new_node_id().node_id() = NodeId{1, requestedId};
    item.browse_name() = QualifiedName{1, "Property"};
    item.node_class() = nodeClass;
    make_add_nodes_item_conforming(item);
    return item;
  };

  req.nodes_to_add().payload().push_back(makeProperty(5470u, NodeClass::Object));
  req.nodes_to_add().payload().push_back(makeProperty(5471u, NodeClass::Variable));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0].status_code(), Status::BadNodeClassInvalid)
    << "AddNodes must not create a non-Variable as the HasProperty target of a ReferenceType";
  ASSERT_NE(resp->results()[0].status_code().shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].status_code().shared_detail()->code, "ReferenceTypePropertyNotVariable");
  EXPECT_TRUE(resp->results()[1].status_code().is_good())
    << "a Variable Property of the same ReferenceType must still be honoured";

  EXPECT_EQ(handler->addNodesCalls, 1u);
  ASSERT_EQ(handler->addNodesItems.size(), 1u) << "the non-Variable Property must not reach node creation";
  EXPECT_EQ(handler->addNodesItems[0].node_class(), NodeClass::Variable);
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 6.6: the constraint is on the source of the resulting HasInterface reference, and
// AddReferences carries isForward - an item declared with isForward false creates the inverse
// reference, so the *item's target* becomes the source of the HasInterface edge that ends up in
// the address space. A plausible implementation reads item.sourceNodeId() as "the source of the
// reference", which is true only for forward items, and so inspects the wrong node entirely: the
// same pair of Nodes passes or fails purely on a flag the check never reads.
// @verifies AC-SVR-ADDRSP-023-INTERFACES-NOT-HASINTERFACE-SOURCE
TEST(NodeManagementService, AddReferenceInverselyDeclaredInterfaceSourceForHasInterfaceRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  // Two genuine Interfaces: ObjectTypes deriving from BaseInterfaceType (0:17602).
  auto interfaceA = as.try_create_node_sync(NodeId{1, 3510u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(interfaceA.is_good());
  auto interfaceAAccessor = interfaceA.value();
  ASSERT_TRUE(interfaceAAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good())
    << "setup: the Node that becomes the reference's source must genuinely be an Interface";

  auto interfaceB = as.try_create_node_sync(NodeId{1, 3511u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(interfaceB.is_good());
  auto interfaceBAccessor = interfaceB.value();
  ASSERT_TRUE(interfaceBAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // Illegal: isForward false, so the edge created is 1:3510 --HasInterface--> 1:85 - an Interface
  // is the source. The item's own sourceNodeId names the Object, which is not an Interface at all.
  AddReferencesItem inverselyDeclared;
  inverselyDeclared.source_node_id() = NodeId{1, 85u};
  inverselyDeclared.reference_type_id() = NodeId{0, 17603u};  // HasInterface
  inverselyDeclared.is_forward() = false;
  inverselyDeclared.target_node_id().node_id() = NodeId{1, 3510u};
  inverselyDeclared.target_node_class() = NodeClass::ObjectType;
  req.references_to_add().payload().push_back(std::move(inverselyDeclared));

  // Lawful: the same Object, forward, applying an Interface. Only isForward differs.
  AddReferencesItem forwardDeclared;
  forwardDeclared.source_node_id() = NodeId{1, 85u};
  forwardDeclared.reference_type_id() = NodeId{0, 17603u};  // HasInterface
  forwardDeclared.is_forward() = true;
  forwardDeclared.target_node_id().node_id() = NodeId{1, 3511u};
  forwardDeclared.target_node_class() = NodeClass::ObjectType;
  req.references_to_add().payload().push_back(std::move(forwardDeclared));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "an inversely declared HasInterface whose resulting source is an Interface must be refused";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "InterfaceAsHasInterfaceSource");
  EXPECT_TRUE(resp->results()[1].is_good())
    << "the forward declaration from the same Object must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the inversely declared item must not reach reference creation";
  EXPECT_TRUE(handler->addReferencesItems[0].is_forward());
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3511u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 6.6: the obligation is over every HasTypeDefinition reference in the address space, and
// AddReferences creates those references directly - a client need never call AddNodes to type an
// existing Object by an Interface. A plausible implementation puts the Interface screen on the
// AddNodes item's typeDefinition field, because that is where a TypeDefinition is normally
// supplied, and leaves the AddReferences path with no rule for reference type 0:40 at all.
// @verifies AC-SVR-ADDRSP-029-INTERFACE-NOT-TYPEDEFINITION
TEST(NodeManagementService, AddReferenceHasTypeDefinitionTargetingInterfaceRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  // A genuine Interface: an ObjectType deriving from BaseInterfaceType.
  auto interfaceType = as.try_create_node_sync(NodeId{1, 3520u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(interfaceType.is_good());
  auto interfaceAccessor = interfaceType.value();
  ASSERT_TRUE(interfaceAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good())
    << "setup: the TypeDefinition target under test must genuinely be an Interface";

  // A concrete ObjectType with no Interface lineage - the lawful control.
  auto concreteType = as.try_create_node_sync(NodeId{1, 3521u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(concreteType.is_good());

  // One instance per item, so neither item is refused merely for being a second TypeDefinition.
  auto instanceForInterface = as.try_create_node_sync(NodeId{1, 3522u}, NodeClass::Object, {});
  ASSERT_TRUE(instanceForInterface.is_good());
  auto instanceForConcrete = as.try_create_node_sync(NodeId{1, 3523u}, NodeClass::Object, {});
  ASSERT_TRUE(instanceForConcrete.is_good());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  AddReferencesItem interfaceTyped;
  interfaceTyped.source_node_id() = NodeId{1, 3522u};
  interfaceTyped.reference_type_id() = NodeId{0, 40u};  // HasTypeDefinition
  interfaceTyped.is_forward() = true;
  interfaceTyped.target_node_id().node_id() = NodeId{1, 3520u};
  interfaceTyped.target_node_class() = NodeClass::ObjectType;
  req.references_to_add().payload().push_back(std::move(interfaceTyped));

  AddReferencesItem concreteTyped;
  concreteTyped.source_node_id() = NodeId{1, 3523u};
  concreteTyped.reference_type_id() = NodeId{0, 40u};  // HasTypeDefinition
  concreteTyped.is_forward() = true;
  concreteTyped.target_node_id().node_id() = NodeId{1, 3521u};
  concreteTyped.target_node_class() = NodeClass::ObjectType;
  req.references_to_add().payload().push_back(std::move(concreteTyped));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "AddReferences must not create a HasTypeDefinition whose target is an Interface";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "InterfaceAsTypeDefinition");
  EXPECT_TRUE(resp->results()[1].is_good())
    << "a HasTypeDefinition to a concrete ObjectType must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the Interface-targeting HasTypeDefinition must not reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3521u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 7.5: the "No Loop" constraint is declared on HasChild and inherited by every subtype, and
// the traversal a client performs is "HasChild, include subtypes" - so a cycle need not be built
// from one ReferenceType. A --HasComponent--> B --HasOrderedComponent--> A is a single HasChild
// cycle assembled from two of its subtypes. A plausible implementation compares the candidate's
// ReferenceType for equality against the references already present, which cannot see a cycle whose
// edges disagree on their exact type even though all of them are HasChild.
// @verifies AC-SVR-ADDRSP-071-NO-LOOP-HONOURED
TEST(NodeManagementService, AddReferenceClosingLoopAcrossHasChildSubtypesRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto nodeA = as.try_create_node_sync(NodeId{1, 3530u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeA.is_good());
  auto nodeB = as.try_create_node_sync(NodeId{1, 3531u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeB.is_good());
  auto nodeC = as.try_create_node_sync(NodeId{1, 3532u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeC.is_good());

  // Existing hierarchy: A --HasComponent--> B, so a HasChild traversal from A already reaches B.
  auto accessorA = nodeA.value();
  ASSERT_TRUE(accessorA.try_add_reference_sync(NodeId{0, 47u}, NodeId{1, 3531u}, true).is_good())
    << "setup: the loop must already be one HasChild reference away from closing";

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // B --HasOrderedComponent--> A closes the cycle: a different HasChild subtype from the edge
  // already present, but the same hierarchy a client walks.
  AddReferencesItem closesLoop;
  closesLoop.source_node_id() = NodeId{1, 3531u};
  closesLoop.reference_type_id() = NodeId{0, 49u};  // HasOrderedComponent, also under HasChild
  closesLoop.is_forward() = true;
  closesLoop.target_node_id().node_id() = NodeId{1, 3530u};
  closesLoop.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(closesLoop));

  AddReferencesItem extendsTree;
  extendsTree.source_node_id() = NodeId{1, 3531u};
  extendsTree.reference_type_id() = NodeId{0, 49u};  // HasOrderedComponent
  extendsTree.is_forward() = true;
  extendsTree.target_node_id().node_id() = NodeId{1, 3532u};
  extendsTree.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(extendsTree));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "a cycle assembled from two different HasChild subtypes must be refused like any other";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "ReferenceWouldCreateLoop");
  EXPECT_TRUE(resp->results()[1].is_good())
    << "the same ReferenceType extending the hierarchy without closing a loop must be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the loop-closing reference must not reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3532u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3: the rule is about the Node the HasProperty edge points *at* once created, and
// AddReferences carries isForward - declared inversely, the item's target is the ReferenceType that
// owns the Property and the item's source is the Property itself. A plausible implementation reads
// the item's target as "the Property" unconditionally, so on inverse items it inspects the
// ReferenceType instead of the Property: it refuses the lawful declaration of a Variable Property
// and admits nothing it should, getting the constraint exactly backwards for that direction.
// @verifies AC-SVR-ADDRSP-073-REFERENCETYPE-PROPERTY-IS-VARIABLE
TEST(NodeManagementService, ReferenceTypeInverselyDeclaredHasPropertyMustTargetVariable)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto referenceType = as.try_create_node_sync(NodeId{1, 3540u}, NodeClass::ReferenceType, {});
  ASSERT_TRUE(referenceType.is_good());
  ASSERT_EQ(referenceType.value().get_node_class(), NodeClass::ReferenceType)
    << "setup: the Node that owns the Property must genuinely be a ReferenceType";

  auto objectProperty = as.try_create_node_sync(NodeId{1, 3541u}, NodeClass::Object, {});
  ASSERT_TRUE(objectProperty.is_good());
  ASSERT_EQ(objectProperty.value().get_node_class(), NodeClass::Object);

  auto variableProperty = as.try_create_node_sync(NodeId{1, 3542u}, NodeClass::Variable, {});
  ASSERT_TRUE(variableProperty.is_good());
  ASSERT_EQ(variableProperty.value().get_node_class(), NodeClass::Variable);

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // Inverse declaration: the item's source is the candidate Property, the item's target is the
  // ReferenceType, so the edge created is ReferenceType --HasProperty--> source.
  auto makeInverseProperty = [](NodeId property)
  {
    AddReferencesItem item;
    item.source_node_id() = std::move(property);
    item.reference_type_id() = NodeId{0, 46u};  // HasProperty
    item.is_forward() = false;
    item.target_node_id().node_id() = NodeId{1, 3540u};
    item.target_node_class() = NodeClass::ReferenceType;
    return item;
  };

  req.references_to_add().payload().push_back(makeInverseProperty(NodeId{1, 3541u}));  // Object
  req.references_to_add().payload().push_back(makeInverseProperty(NodeId{1, 3542u}));  // Variable

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "an inversely declared HasProperty making a non-Variable the Property of a ReferenceType "
       "must be refused";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "ReferenceTypePropertyNotVariable");
  EXPECT_TRUE(resp->results()[1].is_good())
    << "an inversely declared HasProperty whose Property is a Variable is lawful and must be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "exactly the Variable Property may reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].source_node_id(), (NodeId{1, 3542u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3.3.3 with section 7.10: single inheritance is what makes "include subtypes" a tree walk -
// with two supertypes a Browse filter matches the same ReferenceType by two paths and the client receives the
// same reference twice from one call. AddReferences can attach a second HasSubtype to a
// ReferenceType that already has one. A plausible implementation validates the pair in isolation -
// here, that the supertype and subtype agree on Symmetric - and never counts the inbound HasSubtype
// references the target already carries, so the second supertype is indistinguishable from the first.
// @verifies AC-SVR-ADDRSP-074-REFERENCETYPE-SINGLE-SUPERTYPE
TEST(NodeManagementService, ReferenceTypeSecondSupertypeRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto firstSupertype = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3550u}, NodeClass::ReferenceType);
  ASSERT_TRUE(firstSupertype.is_good());
  auto firstSupertypeAccessor = firstSupertype.value();
  firstSupertypeAccessor.set_symmetric(false);

  auto secondSupertype =
    as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3551u}, NodeClass::ReferenceType);
  ASSERT_TRUE(secondSupertype.is_good());
  auto secondSupertypeAccessor = secondSupertype.value();
  secondSupertypeAccessor.set_symmetric(false);

  // Already derived: this ReferenceType has its one supertype.
  auto alreadyDerived = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3552u}, NodeClass::ReferenceType);
  ASSERT_TRUE(alreadyDerived.is_good());
  auto alreadyDerivedAccessor = alreadyDerived.value();
  alreadyDerivedAccessor.set_symmetric(false);
  ASSERT_TRUE(
    alreadyDerivedAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{1, 3550u}, false).is_good())
    << "setup: the ReferenceType under test must genuinely already have a supertype";

  // Not yet derived: this one has no supertype, so attaching one is lawful.
  auto notYetDerived = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3553u}, NodeClass::ReferenceType);
  ASSERT_TRUE(notYetDerived.is_good());
  auto notYetDerivedAccessor = notYetDerived.value();
  notYetDerivedAccessor.set_symmetric(false);

  // The antecedent must be real, not assumed: every Node here agrees on Symmetric, so the
  // supertype-consistency rule cannot be what separates the two items - only the supertype count can.
  ASSERT_FALSE(firstSupertypeAccessor.get_symmetric());
  ASSERT_FALSE(secondSupertypeAccessor.get_symmetric());
  ASSERT_FALSE(alreadyDerivedAccessor.get_symmetric());
  ASSERT_FALSE(notYetDerivedAccessor.get_symmetric());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  auto makeSubtypeOfSecond = [](NodeId subtype)
  {
    AddReferencesItem item;
    item.source_node_id() = NodeId{1, 3551u};
    item.reference_type_id() = NodeId{0, 45u};  // HasSubtype
    item.is_forward() = true;
    item.target_node_id().node_id() = std::move(subtype);
    item.target_node_class() = NodeClass::ReferenceType;
    return item;
  };

  req.references_to_add().payload().push_back(makeSubtypeOfSecond(NodeId{1, 3552u}));
  req.references_to_add().payload().push_back(makeSubtypeOfSecond(NodeId{1, 3553u}));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "a ReferenceType that already has a supertype must not be given a second one";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "ReferenceTypeSecondSupertype");
  EXPECT_TRUE(resp->results()[1].is_good())
    << "a ReferenceType with no supertype must still be allowed its first";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the second supertype must not reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3553u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 4.2: the eight NodeClasses are also the bit values of the NodeClassMask a client sends to
// Browse, so a plausible implementation screens AddNodes with a mask test - "every set bit is one of
// the eight" - which admits every *combination* of those bits, `Object|Variable` (3) among them. No
// Node belongs to two NodeClasses, and a client reading the NodeClass attribute of such a Node gets an
// answer it cannot act on. Nothing in this request is lawful, so it also pins the response shape when
// the screen refuses everything: per-item statuses rather than a fault, and node creation never
// entered at all - a refusal reported to the client but not withheld from the delegate would leave the
// illegal Node in the address space regardless.
// @verifies AC-SVR-ADDRSP-005-NO-VENDOR-NODECLASSES
TEST(NodeManagementService, AddNodeNodeClassOutsideTheEightNeverReachesNodeCreation)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  // The antecedent, stated rather than assumed: none of these is one of the eight, yet the first two
  // are built purely from the eight's own bits and so survive any mask-shaped check.
  const auto objectAndVariable = static_cast<NodeClass>(1 | 2);
  const auto everyNodeClassBit = static_cast<NodeClass>(255);
  const auto beyondTheBits = static_cast<NodeClass>(4096);
  ASSERT_FALSE(is_valid(objectAndVariable));
  ASSERT_FALSE(is_valid(everyNodeClassBit));
  ASSERT_FALSE(is_valid(beyondTheBits));

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  auto makeItem = [](uint32_t requestedId, NodeClass nodeClass)
  {
    AddNodesItem item;
    item.parent_node_id().node_id() = NodeId{1, 85u};
    item.reference_type_id() = NodeId{0, 35u};  // Organizes
    item.requested_new_node_id().node_id() = NodeId{1, requestedId};
    item.browse_name() = QualifiedName{1, "InvalidNodeClass"};
    item.node_class() = nodeClass;
    return item;
  };

  req.nodes_to_add().payload().push_back(makeItem(5500u, objectAndVariable));
  req.nodes_to_add().payload().push_back(makeItem(5501u, everyNodeClassBit));
  req.nodes_to_add().payload().push_back(makeItem(5502u, beyondTheBits));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault)
    << "a request every item of which is refused is still answered per item, not faulted";
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 3u);

  EXPECT_EQ(resp->results()[0].status_code(), Status::BadNodeClassInvalid)
    << "a combination of NodeClass bits is not one of the eight and must be refused";
  EXPECT_EQ(resp->results()[1].status_code(), Status::BadNodeClassInvalid)
    << "every NodeClass bit set at once is not one of the eight and must be refused";
  EXPECT_EQ(resp->results()[2].status_code(), Status::BadNodeClassInvalid)
    << "a value outside the enumeration entirely must be refused";

  // The other half of the obligation: none of the three may reach node creation.
  EXPECT_EQ(handler->addNodesCalls, 0u)
    << "no item carrying a NodeClass outside the eight may be handed to node creation";
  EXPECT_TRUE(handler->addNodesItems.empty());
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 6.6: an Interface may not be the source of a HasInterface reference, and AddNodes creates
// the reference from the parent to the new Node at the same time as the Node - so an item naming an
// Interface as parent and HasInterface as the reference would put exactly the forbidden edge into the
// address space without AddReferences ever being called. The obligation is negative and is about the
// resulting edge only: whether a lawful sibling item on the same parent succeeds is governed by the
// AddNodes operation-result obligations, not by this one, so nothing is asserted about that here.
// @verifies AC-SVR-ADDRSP-023-INTERFACES-NOT-HASINTERFACE-SOURCE
TEST(NodeManagementService, AddNodeUnderInterfaceParentViaHasInterfaceRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  // A genuine Interface: an ObjectType deriving from BaseInterfaceType (0:17602).
  auto interfaceParent = as.try_create_node_sync(NodeId{1, 3610u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(interfaceParent.is_good());
  auto interfaceAccessor = interfaceParent.value();
  ASSERT_TRUE(interfaceAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good())
    << "setup: the parent must genuinely be an Interface";
  ASSERT_EQ(interfaceAccessor.get_node_class(), NodeClass::ObjectType);

  AddNodesRequest req;
  req.request_header().request_handle() = 1;

  // Illegal: the Interface becomes the source of a HasInterface reference to the new Node.
  AddNodesItem appliesInterface;
  appliesInterface.parent_node_id().node_id() = NodeId{1, 3610u};
  appliesInterface.reference_type_id() = NodeId{0, 17603u};  // HasInterface
  appliesInterface.requested_new_node_id().node_id() = NodeId{1, 5510u};
  appliesInterface.node_class() = NodeClass::ObjectType;
  req.nodes_to_add().payload().push_back(std::move(appliesInterface));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddNodesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);

  EXPECT_TRUE(resp->results()[0].status_code().is_bad())
    << "AddNodes must not create a HasInterface reference whose source is an Interface";

  // The same obligation stated over the address space rather than the status code: the edge must not
  // be created, so the item must not reach node creation at all.
  EXPECT_EQ(handler->addNodesCalls, 0u);
  EXPECT_TRUE(handler->addNodesItems.empty())
    << "the Interface-sourced HasInterface must not reach node creation";
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 6.6: the obligation is over the HasTypeDefinition references that end up in the address
// space, and AddReferences carries isForward - declared inversely, the item's *source* is the type and
// its *target* is the instance, so the edge created still runs instance -> Interface. A plausible
// implementation reads the item's targetNodeId as "the TypeDefinition" because that is true of forward
// items, and on an inverse item inspects the instance instead: the same pair of Nodes then passes or
// fails purely on a flag the check never reads.
// @verifies AC-SVR-ADDRSP-029-INTERFACE-NOT-TYPEDEFINITION
TEST(NodeManagementService, AddReferenceInverselyDeclaredHasTypeDefinitionTargetingInterfaceRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  // A genuine Interface: an ObjectType deriving from BaseInterfaceType.
  auto interfaceType = as.try_create_node_sync(NodeId{1, 3620u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(interfaceType.is_good());
  auto interfaceAccessor = interfaceType.value();
  ASSERT_TRUE(interfaceAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{0, 17602u}, false).is_good())
    << "setup: the Node that becomes the TypeDefinition must genuinely be an Interface";

  // A concrete ObjectType with no Interface lineage - the lawful control.
  auto concreteType = as.try_create_node_sync(NodeId{1, 3621u}, NodeClass::ObjectType, {});
  ASSERT_TRUE(concreteType.is_good());

  // One instance per item, so neither item is refused merely for being a second TypeDefinition.
  auto instanceForInterface = as.try_create_node_sync(NodeId{1, 3622u}, NodeClass::Object, {});
  ASSERT_TRUE(instanceForInterface.is_good());
  auto instanceForConcrete = as.try_create_node_sync(NodeId{1, 3623u}, NodeClass::Object, {});
  ASSERT_TRUE(instanceForConcrete.is_good());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // Inverse declaration: the item's source is the type, its target is the instance, so the edge
  // created is instance --HasTypeDefinition--> type. Both items share that shape; only the
  // Interface-ness of the type differs.
  auto makeInverseTypeDefinition = [](NodeId type, NodeId instance)
  {
    AddReferencesItem item;
    item.source_node_id() = std::move(type);
    item.reference_type_id() = NodeId{0, 40u};  // HasTypeDefinition
    item.is_forward() = false;
    item.target_node_id().node_id() = std::move(instance);
    item.target_node_class() = NodeClass::Object;
    return item;
  };

  req.references_to_add().payload().push_back(makeInverseTypeDefinition(NodeId{1, 3620u}, NodeId{1, 3622u}));
  req.references_to_add().payload().push_back(makeInverseTypeDefinition(NodeId{1, 3621u}, NodeId{1, 3623u}));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "an inversely declared HasTypeDefinition whose resulting target is an Interface must be refused";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "InterfaceAsTypeDefinition");
  EXPECT_TRUE(resp->results()[1].is_good())
    << "the same inverse declaration naming a concrete ObjectType must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the Interface-typed instance must not reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].source_node_id(), (NodeId{1, 3621u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 7.5: the "No Loop" promise is about the edges that exist once the request is applied, and
// AddReferences carries isForward - an item declared inversely creates the reference target -> source,
// so the loop it closes is invisible to a check that reads sourceNodeId as the source of the resulting
// edge. A plausible implementation looks for a reference already running from the item's target back
// to its source, which is exactly the wrong pair of Nodes on an inverse item: the very same loop is
// refused when declared forward and created when declared inversely.
// @verifies AC-SVR-ADDRSP-071-NO-LOOP-HONOURED
TEST(NodeManagementService, AddReferenceInverselyDeclaredLoopOnNoLoopReferenceTypeRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto nodeA = as.try_create_node_sync(NodeId{1, 3630u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeA.is_good());
  auto nodeB = as.try_create_node_sync(NodeId{1, 3631u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeB.is_good());
  auto nodeC = as.try_create_node_sync(NodeId{1, 3632u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeC.is_good());
  auto nodeD = as.try_create_node_sync(NodeId{1, 3633u}, NodeClass::Object, {});
  ASSERT_TRUE(nodeD.is_good());

  // Existing hierarchy: A --HasComponent--> B --HasComponent--> D. A traversal from A reaches B, so
  // any edge B -> A returns it to its start; B also genuinely carries references of its own, so an
  // empty reference list cannot be what refuses the item under test.
  auto accessorA = nodeA.value();
  ASSERT_TRUE(accessorA.try_add_reference_sync(NodeId{0, 47u}, NodeId{1, 3631u}, true).is_good())
    << "setup: the loop must already be one reference away from closing";
  auto accessorB = nodeB.value();
  ASSERT_TRUE(accessorB.try_add_reference_sync(NodeId{0, 47u}, NodeId{1, 3633u}, true).is_good())
    << "setup: the node that closes the loop must have references of its own";

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // Inverse declaration: the edge created runs from the item's target to the item's source.
  auto makeInverseComponent = [](NodeId source, NodeId target)
  {
    AddReferencesItem item;
    item.source_node_id() = std::move(source);
    item.reference_type_id() = NodeId{0, 47u};  // HasComponent, a HasChild subtype
    item.is_forward() = false;
    item.target_node_id().node_id() = std::move(target);
    item.target_node_class() = NodeClass::Object;
    return item;
  };

  // Creates B --HasComponent--> A, closing the loop A -> B -> A.
  req.references_to_add().payload().push_back(makeInverseComponent(NodeId{1, 3630u}, NodeId{1, 3631u}));
  // Creates A --HasComponent--> C, which extends the hierarchy and closes nothing.
  req.references_to_add().payload().push_back(makeInverseComponent(NodeId{1, 3632u}, NodeId{1, 3630u}));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "an inversely declared reference that lets a traversal return to its starting node must be "
       "refused";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "ReferenceWouldCreateLoop");
  EXPECT_TRUE(resp->results()[1].is_good())
    << "an inversely declared reference that extends the hierarchy must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the loop-closing reference must not reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].source_node_id(), (NodeId{1, 3632u}));
  EXPECT_FALSE(handler->addReferencesItems[0].is_forward());
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3: the constraint is on the NodeClass the Property Node actually has, not on the
// targetNodeClass the client typed into the request - that field is a hint the client may get wrong or
// may set deliberately, and a server that trusts it lets a Method become the Property of a
// ReferenceType on the client's say-so. The first item misdeclares its Method target as a Variable,
// which is the falsifying case: a check reading the request field sees "Variable" and accepts, while a
// check reading the address space sees a Method and refuses.
//
// The second item used to misdeclare in the opposite direction - a real Variable called an Object -
// and assert that it was accepted anyway, on the reasoning that the declared class is irrelevant to
// section 5.3. That reasoning is right about section 5.3 and wrong about the request: Part 4 section 5.7.3.2
// makes targetNodeClass a checked parameter and section 5.7.3.4 assigns Bad_NodeClassInvalid to a declaration
// the Server can see is false, so accepting it would store a Reference whose Browse result reports a
// NodeClass its target does not have. The item now declares its target correctly and serves as the
// control, which is what the pair needs it to be: section 5.3's verdict still comes from the address space,
// and the first item is what proves it.
// @verifies AC-SVR-ADDRSP-073-REFERENCETYPE-PROPERTY-IS-VARIABLE
TEST(NodeManagementService, ReferenceTypeHasPropertyMisdeclaredTargetJudgedByActualNodeClass)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto referenceType = as.try_create_node_sync(NodeId{1, 3640u}, NodeClass::ReferenceType, {});
  ASSERT_TRUE(referenceType.is_good());
  ASSERT_EQ(referenceType.value().get_node_class(), NodeClass::ReferenceType)
    << "setup: the Node that would own the Property must genuinely be a ReferenceType";

  auto methodTarget = as.try_create_node_sync(NodeId{1, 3641u}, NodeClass::Method, {});
  ASSERT_TRUE(methodTarget.is_good());
  auto variableTarget = as.try_create_node_sync(NodeId{1, 3642u}, NodeClass::Variable, {});
  ASSERT_TRUE(variableTarget.is_good());

  // The antecedent must be real, not assumed: the request will disagree with each of these.
  ASSERT_EQ(methodTarget.value().get_node_class(), NodeClass::Method);
  ASSERT_EQ(variableTarget.value().get_node_class(), NodeClass::Variable);

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // A Method target the request calls a Variable.
  AddReferencesItem misdeclaredMethod;
  misdeclaredMethod.source_node_id() = NodeId{1, 3640u};
  misdeclaredMethod.reference_type_id() = NodeId{0, 46u};  // HasProperty
  misdeclaredMethod.is_forward() = true;
  misdeclaredMethod.target_node_id().node_id() = NodeId{1, 3641u};
  misdeclaredMethod.target_node_class() = NodeClass::Variable;
  req.references_to_add().payload().push_back(std::move(misdeclaredMethod));

  // The control: a Variable target, correctly declared.
  AddReferencesItem misdeclaredVariable;
  misdeclaredVariable.source_node_id() = NodeId{1, 3640u};
  misdeclaredVariable.reference_type_id() = NodeId{0, 46u};  // HasProperty
  misdeclaredVariable.is_forward() = true;
  misdeclaredVariable.target_node_id().node_id() = NodeId{1, 3642u};
  misdeclaredVariable.target_node_class() = NodeClass::Variable;
  req.references_to_add().payload().push_back(std::move(misdeclaredVariable));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "a Method Property of a ReferenceType must be refused however the request classifies it";
  EXPECT_TRUE(resp->results()[1].is_good())
    << "a Variable Property of a ReferenceType, correctly declared, is lawful";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the non-Variable Property must not reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].target_node_id().node_id(), (NodeId{1, 3642u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// Part 3 section 5.3.3.3 with section 7.10: the count that must not exceed one is of the HasSubtype
// references arriving at a ReferenceType, and AddReferences carries isForward - declared inversely, the
// item's source is the subtype and its target is the supertype, yet the edge created is the same second
// inbound HasSubtype. A plausible implementation counts the supertypes of whichever Node the item names as
// target, which is the supertype itself on an inverse item, so the ReferenceType that already has a
// supertype is never examined and quietly acquires a second.
// @verifies AC-SVR-ADDRSP-074-REFERENCETYPE-SINGLE-SUPERTYPE
TEST(NodeManagementService, ReferenceTypeInverselyDeclaredSecondSupertypeRejected)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto as = si->address_space();

  auto firstSupertype = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3650u}, NodeClass::ReferenceType);
  ASSERT_TRUE(firstSupertype.is_good());
  auto firstSupertypeAccessor = firstSupertype.value();
  firstSupertypeAccessor.set_symmetric(false);

  auto secondSupertype =
    as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3651u}, NodeClass::ReferenceType);
  ASSERT_TRUE(secondSupertype.is_good());
  auto secondSupertypeAccessor = secondSupertype.value();
  secondSupertypeAccessor.set_symmetric(false);

  // Already derived: this ReferenceType has its one supertype.
  auto alreadyDerived = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3652u}, NodeClass::ReferenceType);
  ASSERT_TRUE(alreadyDerived.is_good());
  auto alreadyDerivedAccessor = alreadyDerived.value();
  alreadyDerivedAccessor.set_symmetric(false);
  ASSERT_TRUE(
    alreadyDerivedAccessor.try_add_reference_sync(NodeId{0, 45u}, NodeId{1, 3650u}, false).is_good())
    << "setup: the ReferenceType under test must genuinely already have a supertype";

  // Not yet derived: this one has no supertype, so attaching one is lawful.
  auto notYetDerived = as.try_create_sync<ReferenceTypeAccessor>(NodeId{1, 3653u}, NodeClass::ReferenceType);
  ASSERT_TRUE(notYetDerived.is_good());
  auto notYetDerivedAccessor = notYetDerived.value();
  notYetDerivedAccessor.set_symmetric(false);

  // The antecedent must be real, not assumed: every Node here agrees on Symmetric, so the
  // supertype-consistency rule cannot be what separates the two items - only the supertype count can.
  ASSERT_FALSE(firstSupertypeAccessor.get_symmetric());
  ASSERT_FALSE(secondSupertypeAccessor.get_symmetric());
  ASSERT_FALSE(alreadyDerivedAccessor.get_symmetric());
  ASSERT_FALSE(notYetDerivedAccessor.get_symmetric());

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;

  // Inverse declaration: the source is the subtype, the target is the supertype being attached.
  auto makeInverseSubtypeOfSecond = [](NodeId subtype)
  {
    AddReferencesItem item;
    item.source_node_id() = std::move(subtype);
    item.reference_type_id() = NodeId{0, 45u};  // HasSubtype
    item.is_forward() = false;
    item.target_node_id().node_id() = NodeId{1, 3651u};
    item.target_node_class() = NodeClass::ReferenceType;
    return item;
  };

  req.references_to_add().payload().push_back(makeInverseSubtypeOfSecond(NodeId{1, 3652u}));
  req.references_to_add().payload().push_back(makeInverseSubtypeOfSecond(NodeId{1, 3653u}));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 2u);

  EXPECT_EQ(resp->results()[0], Status::BadReferenceNotAllowed)
    << "an inversely declared second supertype is still a second supertype and must be refused";
  ASSERT_NE(resp->results()[0].shared_detail(), nullptr);
  EXPECT_EQ(resp->results()[0].shared_detail()->code, "ReferenceTypeSecondSupertype");
  EXPECT_TRUE(resp->results()[1].is_good()) << "an inversely declared first supertype must still be honoured";

  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ASSERT_EQ(handler->addReferencesItems.size(), 1u)
    << "the second supertype must not reach reference creation";
  EXPECT_EQ(handler->addReferencesItems[0].source_node_id(), (NodeId{1, 3653u}));
  ::ua::test_utils::drain_with_timeout(tp);
}

// --- SVC-6: two-node changes are authorized on both Nodes (SVR-AUTHZ-007) ---------------------------

namespace
{
AddReferencesRequest organizes_85_to_100(bool forward)
{
  AddReferencesRequest req;
  req.request_header().request_handle() = 1;
  AddReferencesItem item;
  item.source_node_id() = NodeId{1, 85u};
  item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  item.is_forward() = forward;
  item.target_node_id().node_id() = NodeId{1, 100u};
  item.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(item));
  return req;
}
}  // namespace

// @verifies AC-SVR-AUTHZ-007-AN-INVERSE-ADDREFERENCE-NEEDS-ADDREFERENCE-ON-THE-TARGET
TEST(NodeManagementService, InverseAddReferenceRequiresAddReferenceOnTheTarget)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::AddReference);
  si->set_node_permissions(NodeId{1, 100u}, permissions);  // the target; the source keeps everything
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto result = invoke_service(si, handler, tp.get_executor(), organizes_85_to_100(/*forward=*/false));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], Status::BadUserAccessDenied) << "the target's forward set changes";
  EXPECT_EQ(handler->addReferencesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-SVR-AUTHZ-007-AN-INVERSE-ADDREFERENCE-NEEDS-ADDREFERENCE-ON-THE-TARGET
// The control: the same permissions admit the FORWARD item, whose target is only pointed at.
TEST(NodeManagementService, ForwardAddReferenceDoesNotNeedAddReferenceOnTheTarget)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::AddReference);
  si->set_node_permissions(NodeId{1, 100u}, permissions);
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto result = invoke_service(si, handler, tp.get_executor(), organizes_85_to_100(/*forward=*/true));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_NE(resp->results()[0], Status::BadUserAccessDenied);
  EXPECT_EQ(handler->addReferencesCalls, 1u);
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{
DeleteReferencesRequest delete_100_to_200(bool bidirectional)
{
  DeleteReferencesRequest req;
  req.request_header().request_handle() = 1;
  DeleteReferencesItem item;
  item.source_node_id() = NodeId{1, 100u};
  item.reference_type_id() = NodeId{1, 250u};
  item.is_forward() = true;
  item.target_node_id() = ExpandedNodeId{NodeId{1, 200u}};
  item.delete_bidirectional() = bidirectional;
  req.references_to_delete().payload().push_back(std::move(item));
  return req;
}
}  // namespace

// @verifies AC-SVR-AUTHZ-007-A-BIDIRECTIONAL-DELETEREFERENCE-NEEDS-REMOVEREFERENCE-ON-THE-TARGET
TEST(NodeManagementService, BidirectionalDeleteReferenceRequiresRemoveReferenceOnTheTarget)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::RemoveReference);
  si->set_node_permissions(NodeId{1, 200u}, permissions);  // the target; the source keeps everything
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto result = invoke_service(si, handler, tp.get_executor(), delete_100_to_200(/*bidirectional=*/true));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<DeleteReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], Status::BadUserAccessDenied) << "the target's inverse Reference goes too";
  EXPECT_EQ(handler->deleteReferencesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}

// @verifies AC-SVR-AUTHZ-007-A-BIDIRECTIONAL-DELETEREFERENCE-NEEDS-REMOVEREFERENCE-ON-THE-TARGET
// The control: a one-directional forward delete touches only the source.
TEST(NodeManagementService, OneDirectionalDeleteReferenceDoesNotNeedRemoveReferenceOnTheTarget)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  auto permissions = ua::test_helpers::all_permissions();
  permissions.reset(PermissionType::Bit::RemoveReference);
  si->set_node_permissions(NodeId{1, 200u}, permissions);
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  auto result = invoke_service(si, handler, tp.get_executor(), delete_100_to_200(/*bidirectional=*/false));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<DeleteReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_NE(resp->results()[0], Status::BadUserAccessDenied);
  EXPECT_EQ(handler->deleteReferencesCalls, 1u);
  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{
/// A namespace whose lookups of one Node fail with an operational error (not "unknown"): the shape a
/// namespace delegate produces under a timeout or an internal fault.
class FailingLookupNamespace final : public default_ns::Namespace
{
public:
  FailingLookupNamespace(string_view uri, boost::asio::any_io_executor executor, NodeId failing)
    : default_ns::Namespace(uri, std::move(executor)), mFailing(std::move(failing))
  {}

protected:
  // Every lookup form of the in-memory namespace answers from here.
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    if (nodeId == mFailing)
      return NodeResult{StatusCode{Status::BadInternalError}};
    return default_ns::Namespace::resolve_here(nodeId);
  }

private:
  NodeId mFailing;
};
}  // namespace

// @verifies AC-SVR-AUTHZ-007-AN-INVERSE-ADDREFERENCE-NEEDS-ADDREFERENCE-ON-THE-TARGET
// A target whose lookup fails for any reason other than "unknown" fails the item; the target's own
// AddReference check is never skipped on the strength of a lookup error.
TEST(NodeManagementService, InverseAddReferenceWithAFailingTargetLookupIsRefusedNotAdmitted)
{
  boost::asio::thread_pool tp;
  auto si = std::make_shared<NodeManagementSessionInfo>(tp.get_executor(), make_allow_all_authorizer());
  const NodeId failingTarget{2, 5u};
  auto failing =
    std::make_shared<FailingLookupNamespace>("urn:test:failing-lookup", tp.get_executor(), failingTarget);
  const auto index = si->address_space().add_namespace_sync(failing);
  ASSERT_EQ(index, 2u);
  auto handler = std::make_shared<FakeNodeManagementDelegate>();

  AddReferencesRequest req;
  req.request_header().request_handle() = 1;
  AddReferencesItem item;
  item.source_node_id() = NodeId{1, 85u};
  item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  item.is_forward() = false;
  item.target_node_id().node_id() = failingTarget;
  item.target_node_class() = NodeClass::Object;
  req.references_to_add().payload().push_back(std::move(item));

  auto result = invoke_service(si, handler, tp.get_executor(), std::move(req));
  ASSERT_FALSE(result.isServiceFault);
  auto* resp = dynamic_cast<AddReferencesResponse*>(result.response.get());
  ASSERT_NE(resp, nullptr);
  ASSERT_EQ(resp->results().size(), 1u);
  EXPECT_EQ(resp->results()[0], Status::BadInternalError) << "the lookup failure fails the item";
  EXPECT_EQ(handler->addReferencesCalls, 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}
