// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 6: Node Management Service Set - Compliance Integration Tests
///
/// Tests covering Part 4 NodeManagement requirements (NM-GEN-*, NM-AN-*, NM-AR-*, NM-DN-*, NM-DR-*).
///
/// The Node Management service is heavily delegated: the SDK handles protocol framing,
/// authorization gates, and operation limits; the application-provided delegate implements
/// the actual AddNodes/DeleteNodes/AddReferences/DeleteReferences logic.
///
/// These tests exercise the full client -> server -> delegate -> address space stack using a
/// BasicNodeManagementDelegate that performs real address space operations.

#include "compliance_helpers.h"
#include "offloading_node_management_delegate.h"
#include "matchers.h"
#include "requests.h"

#include "ua_session_attribute_services.h"
#include "ua_session_node_management_services.h"
#include "ua_session_view_services.h"

#include "ua_add_nodes_item.h"
#include "ua_add_nodes_request.h"
#include "ua_add_nodes_response.h"
#include "ua_add_nodes_result.h"
#include "ua_add_references_item.h"
#include "ua_add_references_request.h"
#include "ua_add_references_response.h"
#include "ua_access_operation.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_nodes_response.h"
#include "ua_delete_references_item.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_instantiation_options.h"
#include "ua_instantiation_service.h"
#include "ua_namespace_delegates.h"
#include "ua_node_subtree.h"
#include "ua_object_attributes.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_variabletype_id.h"
#include "ua_variable_id.h"
#include "ua_array.h"
#include "ua_string.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_server.h"
#include "ua_to_result.h"
#include "ua_transport_address.h"
#include "ua_variable_attributes.h"
#include "ua_to_string.h"
#include "ua_memory_stream.h"
#include "ua_nodeset_import.h"
#include "ua_error_detail_keys.h"

#include <fmt/format.h>

#include "subscription.h"

#include <chrono>
#include <exception>
#include <future>
#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

void prepare_add_nodes_in_requested_or_parent_namespace(
  std::vector<AddNodesItem> items, NodeManagementDelegate::PrepareAddNodesCallback callback) noexcept
{
  try
  {
    BatchResult<NodeManagementDelegate::PrepareAddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (const auto& item : items)
    {
      const auto& requestedNodeId = item.requested_new_node_id().node_id();
      batch.items.emplace_back(NodeManagementDelegate::AddNodeDestination{
        requestedNodeId.is_null() ? item.parent_node_id().node_id().namespace_index()
                                  : requestedNodeId.namespace_index()});
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

}  // namespace

// ===========================================================================
// BasicNodeManagementDelegate: performs real address space operations
// ===========================================================================

class BasicNodeManagementDelegate final : public NodeManagementDelegate
{
public:
  void prepare_add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<AddNodesItem> items,
    NodeManagementDelegate::PrepareAddNodesCallback callback) noexcept override
  {
    prepare_add_nodes_in_requested_or_parent_namespace(std::move(items), std::move(callback));
  }

  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    std::vector<AddNodesResult> results;
    results.reserve(items.size());

    for (auto& authorizedItem : items)
    {
      auto& item = authorizedItem.item;
      AddNodesResult result;
      try
      {
        // Validate parent exists.
        auto parentId = item.parent_node_id().node_id();
        auto parentResult = addressSpace.try_find_node_sync(parentId);
        if (parentResult.is_bad())
        {
          result.status_code() = Status::BadParentNodeIdInvalid;
          results.push_back(std::move(result));
          continue;
        }

        // Validate browse name.
        if (item.browse_name().name().empty())
        {
          result.status_code() = Status::BadBrowseNameInvalid;
          results.push_back(std::move(result));
          continue;
        }

        // Validate node class.
        if (item.node_class() == NodeClass::Unspecified)
        {
          result.status_code() = Status::BadNodeClassInvalid;
          results.push_back(std::move(result));
          continue;
        }

        // Validate serverIndex on requested NodeId.
        if (item.requested_new_node_id().server_index() != 0)
        {
          result.status_code() = Status::BadNodeIdRejected;
          results.push_back(std::move(result));
          continue;
        }

        const auto& requestedNodeId = item.requested_new_node_id().node_id();
        if (!requestedNodeId.is_null() && rejectedRequestedNodeIds.contains(requestedNodeId))
        {
          result.status_code() = Status::BadNodeIdRejected;
          results.push_back(std::move(result));
          continue;
        }

        // Validate reference type.
        auto refTypeResult = addressSpace.try_find_node_sync(item.reference_type_id());
        if (refTypeResult.is_bad())
        {
          result.status_code() = Status::BadReferenceTypeIdInvalid;
          results.push_back(std::move(result));
          continue;
        }

        // Resolve type definition for Object/Variable. Default to BaseObjectType/BaseDataVariableType
        // when null (Part 4, section 5.7.2.2).
        NodeId typeDefId;
        if (item.node_class() == NodeClass::Object || item.node_class() == NodeClass::Variable)
        {
          typeDefId = item.type_definition().node_id();
          if (typeDefId.is_null())
          {
            typeDefId = (item.node_class() == NodeClass::Object)
                          ? NodeId{ObjectTypeId::BaseObjectType}
                          : NodeId{VariableTypeId::BaseDataVariableType};
          }
          // Validate that the type definition exists.
          auto typeDefResult = addressSpace.try_find_node_sync(typeDefId);
          if (typeDefResult.is_bad())
          {
            result.status_code() = Status::BadTypeDefinitionInvalid;
            results.push_back(std::move(result));
            continue;
          }
        }
        else if (!item.type_definition().node_id().is_null())
        {
          // TypeDefinition must be null for non-Object/Variable.
          result.status_code() = Status::BadTypeDefinitionInvalid;
          results.push_back(std::move(result));
          continue;
        }

        // Check for duplicate browse name under same parent.
        auto parent = parentResult.value();
        auto refsResult = parent.try_get_references_sync();
        if (refsResult.is_good())
        {
          for (const auto& ref : refsResult.value())
          {
            if (!ref.is_forward())
              continue;
            auto childResult = addressSpace.try_find_node_sync(ref.target_id().node_id());
            if (childResult.is_good() && childResult.value().get_browse_name() == item.browse_name())
            {
              result.status_code() = Status::BadBrowseNameDuplicated;
              break;
            }
          }
          if (StatusCode{result.status_code()}.is_bad())
          {
            results.push_back(std::move(result));
            continue;
          }
        }

        // Use InstantiationService for Object/Variable to create mandatory children and apply
        // type definition defaults (Part 4, section 5.7.2.1-2).
        if (item.node_class() == NodeClass::Object || item.node_class() == NodeClass::Variable)
        {
          InstantiationService instantiation{addressSpace};
          InstantiationOptions options;
          options.parentReferenceType = item.reference_type_id();

          // Use the client-specified NodeId when present; otherwise allocate the root and its
          // mandatory children in the destination selected during preparation.
          auto requestedId = item.requested_new_node_id().node_id();
          const auto destinationNamespace = authorizedItem.destination.namespaceIndex;
          if (!requestedId.is_null())
          {
            options.nodeIdAllocator = [requestedId, first = true](
                                        uint16_t, const QualifiedName&) mutable -> NodeId
            {
              if (first)
              {
                first = false;
                return requestedId;
              }
              // Child nodes get server-assigned IDs.
              static std::atomic<uint32_t> counter{50000};
              return NodeId{requestedId.namespace_index(), counter++};
            };
          }
          else
          {
            options.nodeIdAllocator = [destinationNamespace](uint16_t, const QualifiedName&) -> NodeId
            {
              static std::atomic<uint32_t> counter{60000};
              return NodeId{destinationNamespace, counter++};
            };
          }

          std::promise<NodeSubtreeResult> promise;
          auto future = promise.get_future();
          if (item.node_class() == NodeClass::Object)
          {
            instantiation.instantiate_object_async(parentId,
              item.browse_name(),
              typeDefId,
              options,
              [&promise](NodeSubtreeResult r) { promise.set_value(std::move(r)); });
          }
          else
          {
            instantiation.instantiate_variable_async(parentId,
              item.browse_name(),
              typeDefId,
              options,
              VariableInstantiationAttributes{},
              [&promise](NodeSubtreeResult r) { promise.set_value(std::move(r)); });
          }
          auto subtreeResult = future.get();

          if (subtreeResult.is_bad())
          {
            result.status_code() = subtreeResult.status_code().as_status();
            results.push_back(std::move(result));
            continue;
          }

          auto subtree = std::move(subtreeResult).value();
          result.status_code() = Status::Good;
          result.added_node_id() = subtree.root();
          subtree.release();
        }
        else
        {
          // Non-Object/Variable: create node directly.
          auto requestedId = item.requested_new_node_id().node_id();
          if (requestedId.is_null())
            requestedId = NodeId{authorizedItem.destination.namespaceIndex, ++mNextNodeId};

          auto createResult = addressSpace.try_create_node_sync(requestedId, item.node_class(), {});
          if (createResult.is_bad())
          {
            if (createResult.status_code().as_status() == Status::BadNodeIdExists)
              result.status_code() = Status::BadNodeIdExists;
            else
              result.status_code() = Status::BadNodeIdRejected;
            results.push_back(std::move(result));
            continue;
          }

          auto node = createResult.value();
          node.set_browse_name(item.browse_name());
          node.set_display_name(LocalizedText{"", String{item.browse_name().name()}});

          // Add reference from parent to new node.
          parent.try_add_reference_sync(item.reference_type_id(), requestedId);

          result.status_code() = Status::Good;
          result.added_node_id() = requestedId;
        }
      }
      catch (const UaException& ex)
      {
        result.status_code() = ex.status();
      }
      catch (...)
      {
        result.status_code() = Status::BadInternalError;
      }
      results.push_back(std::move(result));
    }

    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    batch.items.reserve(results.size());
    for (auto& r : results)
    {
      batch.items.emplace_back(std::move(r));
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<AddReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    std::vector<StatusCode> results;
    results.reserve(items.size());

    for (auto& item : items)
    {
      try
      {
        // Validate source exists.
        auto sourceResult = addressSpace.try_find_node_sync(item.source_node_id());
        if (sourceResult.is_bad())
        {
          results.emplace_back(Status::BadSourceNodeIdInvalid);
          continue;
        }

        // Validate reference type exists.
        auto refTypeResult = addressSpace.try_find_node_sync(item.reference_type_id());
        if (refTypeResult.is_bad())
        {
          results.emplace_back(Status::BadReferenceTypeIdInvalid);
          continue;
        }

        // Validate target node id.
        auto targetId = item.target_node_id().node_id();
        if (targetId.is_null())
        {
          results.emplace_back(Status::BadTargetNodeIdInvalid);
          continue;
        }

        // Check for self-reference.
        if (item.source_node_id() == targetId)
        {
          results.emplace_back(Status::BadInvalidSelfReference);
          continue;
        }

        // Reject non-empty target_server_uri (no remote references supported).
        if (!item.target_server_uri().empty())
        {
          results.emplace_back(Status::BadServerUriInvalid);
          continue;
        }

        // Reject non-zero server_index on target (local-only references).
        if (item.target_node_id().server_index() != 0)
        {
          results.emplace_back(Status::BadReferenceLocalOnly);
          continue;
        }

        // Validate target_node_class matches actual node class if target exists locally.
        if (item.target_node_class() != NodeClass::Unspecified)
        {
          auto targetResult = addressSpace.try_find_node_sync(targetId);
          if (targetResult.is_good())
          {
            auto actualClass = targetResult.value().get_node_class();
            if (actualClass != item.target_node_class())
            {
              results.emplace_back(Status::BadNodeClassInvalid);
              continue;
            }
          }
        }

        // Validate HasSubtype is only valid between type nodes.
        if (item.reference_type_id() == NodeId{ReferenceTypeId::HasSubtype})
        {
          auto sourceClass = sourceResult.value().get_node_class();
          if (sourceClass != NodeClass::ObjectType && sourceClass != NodeClass::VariableType &&
              sourceClass != NodeClass::ReferenceType && sourceClass != NodeClass::DataType)
          {
            results.emplace_back(Status::BadReferenceNotAllowed);
            continue;
          }
        }

        // Check for duplicate reference.
        auto source = sourceResult.value();
        auto refsResult = source.try_get_references_sync();
        if (refsResult.is_good())
        {
          bool duplicate = false;
          for (const auto& ref : refsResult.value())
          {
            if (ref.type_id() == item.reference_type_id() && ref.target_id().node_id() == targetId &&
                ref.is_forward() == item.is_forward())
            {
              duplicate = true;
              break;
            }
          }
          if (duplicate)
          {
            results.emplace_back(Status::BadDuplicateReferenceNotAllowed);
            continue;
          }
        }

        // Add the reference.
        auto addResult = source.try_add_reference_sync(item.reference_type_id(), targetId, item.is_forward());
        results.push_back(addResult.is_good() ? StatusCode{Status::Good} : addResult.status_code());
      }
      catch (const UaException& ex)
      {
        results.emplace_back(ex.status());
      }
      catch (...)
      {
        results.emplace_back(Status::BadInternalError);
      }
    }

    BatchResult<VoidResult> batch;
    batch.items.reserve(results.size());
    for (auto status : results)
    {
      batch.items.emplace_back(status.is_good() ? VoidResult{} : VoidResult{status});
    }
    callback(std::move(batch));
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteNodesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    std::vector<StatusCode> results;
    results.reserve(items.size());

    for (auto& item : items)
    {
      try
      {
        // Reject null NodeId.
        if (item.node_id().is_null())
        {
          results.emplace_back(Status::BadNodeIdInvalid);
          continue;
        }

        // Check delete rights.
        if (protectedNodeIds.count(item.node_id()) > 0)
        {
          results.emplace_back(Status::BadNoDeleteRights);
          continue;
        }

        auto findResult = addressSpace.try_find_node_sync(item.node_id());
        if (findResult.is_bad())
        {
          results.emplace_back(Status::BadNodeIdUnknown);
          continue;
        }

        auto deleteResult = addressSpace.try_delete_node_sync(item.node_id(),
          item.delete_target_references(),
          item.delete_target_references() ? ReferenceHalves::Both : ReferenceHalves::ThisHalfOnly);
        results.push_back(deleteResult.is_good() ? StatusCode{Status::Good} : deleteResult.status_code());
      }
      catch (const UaException& ex)
      {
        results.emplace_back(ex.status());
      }
      catch (...)
      {
        results.emplace_back(Status::BadInternalError);
      }
    }

    BatchResult<VoidResult> batch;
    batch.items.reserve(results.size());
    for (auto status : results)
    {
      batch.items.emplace_back(status.is_good() ? VoidResult{} : VoidResult{status});
    }
    callback(std::move(batch));
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    std::vector<StatusCode> results;
    results.reserve(items.size());

    for (auto& item : items)
    {
      try
      {
        // Reject non-zero server_index on target.
        if (item.target_node_id().server_index() != 0)
        {
          results.emplace_back(Status::BadServerIndexInvalid);
          continue;
        }

        // Check delete rights on source.
        if (protectedNodeIds.count(item.source_node_id()) > 0)
        {
          results.emplace_back(Status::BadNoDeleteRights);
          continue;
        }

        // Validate source exists.
        auto sourceResult = addressSpace.try_find_node_sync(item.source_node_id());
        if (sourceResult.is_bad())
        {
          results.emplace_back(Status::BadSourceNodeIdInvalid);
          continue;
        }

        // Validate reference type.
        auto refTypeResult = addressSpace.try_find_node_sync(item.reference_type_id());
        if (refTypeResult.is_bad())
        {
          results.emplace_back(Status::BadReferenceTypeIdInvalid);
          continue;
        }

        // Validate target.
        auto targetId = item.target_node_id().node_id();
        if (targetId.is_null())
        {
          results.emplace_back(Status::BadTargetNodeIdInvalid);
          continue;
        }

        // Remove the reference: both halves for deleteBidirectional TRUE, the named half alone for FALSE.
        auto source = sourceResult.value();
        auto removeResult = source.try_remove_reference_sync(item.reference_type_id(),
          targetId,
          item.is_forward(),
          item.delete_bidirectional() ? ReferenceHalves::Both : ReferenceHalves::ThisHalfOnly);
        results.push_back(removeResult.is_good() ? StatusCode{Status::Good} : removeResult.status_code());
      }
      catch (const UaException& ex)
      {
        results.emplace_back(ex.status());
      }
      catch (...)
      {
        results.emplace_back(Status::BadInternalError);
      }
    }

    BatchResult<VoidResult> batch;
    batch.items.reserve(results.size());
    for (auto status : results)
    {
      batch.items.emplace_back(status.is_good() ? VoidResult{} : VoidResult{status});
    }
    callback(std::move(batch));
  }

  std::unordered_set<NodeId> protectedNodeIds;
  std::unordered_set<NodeId> rejectedRequestedNodeIds;

private:
  uint32_t mNextNodeId{50000};
};

// ===========================================================================
// Fixture: ComplianceNodeManagement - server with BasicNodeManagementDelegate
// ===========================================================================

class ComplianceNodeManagement : public ::testing::Test
{
protected:
  void SetUp() override
  {

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;
    // Subclasses may tighten the instantiation budget before the server is built.
    if (mInstantiationDepthLimit)
      appCfg.execution_limits().instantiationDepthLimit = *mInstantiationDepthLimit;

    server::CreateConfig createCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = ServerConfig{}};

    auto logSink = test_log_sink();
    mServer.emplace(server::Server::create(mServerThreadPool.executor(),
      std::move(createCfg),
      server::ServerComponents{.crypto = ua::test_helpers::test_crypto(),
        .authenticator = std::make_shared<AnonymousAuthenticator>(),
        .roleConfiguration = role_configuration(),
        .logSink = logSink,
        .logLevel = LogLevel::Debug}));

    // Install the handler.
    mHandler = std::make_shared<BasicNodeManagementDelegate>();
    mServer->set_node_management_delegate(ua::test::offloaded(mHandler));

    // Create a test namespace with a parent folder.
    auto addressSpace = mServer->address_space();
    mNamespace = default_ns::Namespace::create("urn:test:nodemanagement", mServerThreadPool.executor());
    mNamespaceIndex = addressSpace.add_namespace_sync(mNamespace);
    RolePermissionType namespacePermissions;
    namespacePermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    namespacePermissions.permissions() = all_node_management_permissions();
    mNamespace->set_namespace_defaults(std::vector<RolePermissionType>{namespacePermissions}, std::nullopt);

    // The default above covers this fixture's own nodes, but a test that adds a Node under an NS0 parent
    // - a ReferenceType under NonHierarchicalReferences, say - is authorized against that parent, which
    // lives in a namespace declaring nothing and therefore refusing everything. This grants the
    // namespaces that declare no permissions: it skips the one set just above, and node-level
    // permissions still win over a namespace default, so the per-item denial subjects stand.
    grant_fixture_namespace_permissions(addressSpace);

    mParentFolderId = NodeId{mNamespaceIndex, uint32_t{8000}};
    auto folderNode = addressSpace.create_node_sync(mParentFolderId, NodeClass::Object);
    auto folder = folderNode.as<ObjectAccessor>();
    ASSERT_TRUE(folder.has_value());
    folder->set_browse_name(QualifiedName{mNamespaceIndex, "NMTestFolder"});
    folder->set_display_name(LocalizedText{"", "NMTestFolder"});

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mParentFolderId);

    // Listen + start.
    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListenerHandle = mServer->listen_sync(std::move(bind), {});

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, endpoint);

    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListenerHandle);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    // Client.
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::test_utils::create_test_client_config(),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = logSink, .logLevel = LogLevel::Debug}));

    mChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceNodeManagement"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mClient.reset();
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");
  }

  /// Helper: build an AddNodesItem for creating a Variable under the parent folder.
  AddNodesItem make_add_variable(const QualifiedName& browseName, const NodeId& requestedId = NodeId{})
  {
    AddNodesItem item;
    item.parent_node_id() = ExpandedNodeId{mParentFolderId};
    item.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    item.requested_new_node_id() = ExpandedNodeId{requestedId};
    item.browse_name() = browseName;
    item.node_class() = NodeClass::Variable;
    item.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};
    return item;
  }

  virtual std::shared_ptr<RoleConfiguration> role_configuration()
  {
    return RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  /// Helper: build an AddNodesItem for creating an Object under the parent folder.
  AddNodesItem make_add_object(const QualifiedName& browseName, const NodeId& requestedId = NodeId{})
  {
    AddNodesItem item;
    item.parent_node_id() = ExpandedNodeId{mParentFolderId};
    item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
    item.requested_new_node_id() = ExpandedNodeId{requestedId};
    item.browse_name() = browseName;
    item.node_class() = NodeClass::Object;
    item.type_definition() = ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}};
    return item;
  }

  NodeId build_mandatory_object_chain(std::size_t levels)
  {
    if (levels == 0U)
      return {};

    auto addressSpace = mServer->address_space();
    const NodeId typeId{mNamespaceIndex, std::uint32_t{30000U}};
    auto type = addressSpace.create_node_sync(typeId, NodeClass::ObjectType);
    type.set_browse_name(QualifiedName{mNamespaceIndex, "DepthType"});
    type.set_display_name(LocalizedText{"", "DepthType"});

    NodeId parentDeclarationId;

    for (std::size_t level = 0; level < levels; ++level)
    {
      const auto numericLevel = static_cast<std::uint32_t>(level);
      const NodeId declarationId{mNamespaceIndex, std::uint32_t{30001U + numericLevel}};

      auto declaration = addressSpace.create_node_sync(declarationId, NodeClass::Variable);
      declaration.set_browse_name(QualifiedName{mNamespaceIndex, "DepthChild" + std::to_string(level)});
      declaration.set_display_name(LocalizedText{"", "DepthChild" + std::to_string(level)});
      auto declarationVariable = declaration.as<VariableAccessor>();
      if (!declarationVariable)
      {
        ADD_FAILURE() << "depth declaration was not created as a Variable";
        return {};
      }
      declarationVariable->set_data_type(NodeId{DataTypeId::Int32});
      declarationVariable->set_value_rank(ValueRank{ValueRank::scalar});
      declarationVariable->set_access_level(AccessLevelType{0U});

      declaration.add_reference_sync(
        NodeId{ReferenceTypeId::HasModellingRule}, NodeId{ObjectId::ModellingRule_Mandatory});
      declaration.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});

      if (level == 0U)
      {
        type.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, declarationId);
      }
      else
      {
        auto parentDeclaration = addressSpace.find_node_sync(parentDeclarationId);
        parentDeclaration.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, declarationId);
      }
      parentDeclarationId = declarationId;
    }

    return typeId;
  }

  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::optional<server::Server> mServer;
  server::ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
  std::shared_ptr<BasicNodeManagementDelegate> mHandler;
  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mNamespaceIndex{0};
  std::optional<std::size_t> mInstantiationDepthLimit;
  NodeId mParentFolderId;

  static PermissionType all_node_management_permissions()
  {
    return PermissionType{{PermissionType::Bit::Browse,
      PermissionType::Bit::Read,
      PermissionType::Bit::Write,
      PermissionType::Bit::WriteAttribute,
      PermissionType::Bit::AddReference,
      PermissionType::Bit::RemoveReference,
      PermissionType::Bit::DeleteNode,
      PermissionType::Bit::AddNode}};
  }
};

// A session that MAY add nodes. `well_known_role_permissions` grants Anonymous exactly
// {Browse, Read}; only ConfigureAdmin and SecurityAdmin carry AddNode, and namespace 0 is stamped
// with those derived permissions by `install_server_namespace_defaults`. A ReferenceType is created
// as a subtype of an existing one, and every existing ReferenceType lives in namespace 0, so a
// server-assigned ReferenceType id can only ever be observed by a session holding one of those two
// roles. The refusal an Anonymous session gets is the correct policy, not the subject under test.
class ComplianceNodeManagementAsConfigureAdmin : public ComplianceNodeManagement
{
protected:
  std::shared_ptr<RoleConfiguration> role_configuration() override
  {
    return RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous},
        {WellKnownRole::ConfigureAdmin, IdentityCriteriaType::Anonymous}});
  }
};

class ComplianceNodeManagementNamespaceParity : public ComplianceNodeManagement
{
protected:
  std::shared_ptr<RoleConfiguration> role_configuration() override
  {
    return RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous},
        {WellKnownRole::ConfigureAdmin, IdentityCriteriaType::Anonymous}});
  }
};

// ===========================================================================
// AddNodes - positive smoke tests
// ===========================================================================

// Add a Variable node with attributes, then read it back.
// @relation(SVR-NM-SVC-002, SVR-ADDRSP-009, scope=function)
TEST_F(ComplianceNodeManagement, AddVariableNode)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9000}};
  AddNodesRequest req;
  req.nodes_to_add().push_back(make_add_variable(QualifiedName{mNamespaceIndex, "TestVariable"}, nodeId));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "AddNodes should succeed";
  EXPECT_EQ(resp.results()[0].added_node_id(), nodeId);

  // Verify the node is readable.
  auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::BrowseName));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], Good());
}

// Add an Object node, then browse for it under the parent.
// @relation(SVR-NM-AN-031, SVR-NM-SVC-002, scope=function)
TEST_F(ComplianceNodeManagement, AddObjectNode)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9001}};
  AddNodesRequest req;
  req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "TestObject"}, nodeId));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());

  // Verify the node is browsable from parent.
  auto browseResult = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(browseResult, Good());
  auto browseResp = std::move(browseResult).value();
  ASSERT_EQ(browseResp.results().size(), 1u);

  bool found = false;
  for (const auto& ref : browseResp.results()[0].references())
  {
    if (ref.node_id().node_id() == nodeId)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Added object should be browsable from parent";
}

// ===========================================================================
// AddNodes - requirement tests
// ===========================================================================

// Requirement: SVR-NM-GEN-001 (SHALL)
// All added Nodes continue to exist in the AddressSpace even if the Client that created
// them disconnects from the Server.
// Spec: Part 4, section 5.7.1, line 2602
// @relation(SVR-NM-GEN-001, scope=function)
TEST_F(ComplianceNodeManagement, NM_GEN_001_NodePersistsAfterDisconnect)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9100}};
  AddNodesRequest req;
  req.nodes_to_add().push_back(make_add_variable(QualifiedName{mNamespaceIndex, "PersistentNode"}, nodeId));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good());

  // Close and reopen session.
  mSession->close_sync();
  mChannel->close_sync();
  mChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
  mSession.emplace(mChannel->create_session_sync({.sessionName = "Reconnected"}));
  mSession->activate_sync();

  // The node should still exist.
  auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::BrowseName));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], Good()) << "Node should persist after client disconnect";
}

// Requirement: SVR-NM-AN-003 (SHALL)
// The serverIndex in the requestedNewNodeId expanded NodeId shall be 0.
// Spec: Part 4, section 5.7.2.2, line 2639
// @relation(SVR-NM-AN-003, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_003_ServerIndexZero)
{
  // serverIndex=0 -> accepted.
  AddNodesRequest req;
  auto item = make_add_variable(QualifiedName{mNamespaceIndex, "ServerIndex0"});
  item.requested_new_node_id() =
    ExpandedNodeId{NodeId{mNamespaceIndex, uint32_t{9200}}};  // serverIndex defaults to 0
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "serverIndex=0 should be accepted";
}

// Requirement: SVR-NM-AN-003 (SHALL)
// requestedNewNodeId with serverIndex!=0 -> rejected.
// @relation(SVR-NM-SVC-002, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_003_ServerIndexNonZero_Rejected)
{
  AddNodesRequest req;
  auto item = make_add_variable(QualifiedName{mNamespaceIndex, "ServerIndexNonZero"});
  ExpandedNodeId expId{NodeId{mNamespaceIndex, uint32_t{9201}}};
  expId.server_index() = 1;
  item.requested_new_node_id() = std::move(expId);
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdRejected)) << "serverIndex!=0 shall be rejected";
}

// Requirement: SVR-NM-AN-008 (SHALL)
// TypeDefinition shall be provided for Object and Variable node classes.
// @relation(SVR-NM-AN-008, SVR-NM-AN-029, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_008_TypeDefRequiredForObjectVariable)
{
  AddNodesRequest req;
  auto item =
    make_add_object(QualifiedName{mNamespaceIndex, "WithTypeDef"}, NodeId{mNamespaceIndex, uint32_t{9202}});
  // TypeDefinition is already set by make_add_object.
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Object with TypeDefinition should be accepted";
}

// Requirement: SVR-NM-AN-008 (SHALL)
// TypeDefinition non-null for Method -> rejected.
TEST_F(ComplianceNodeManagement, NM_AN_008_TypeDefNullForNonObjectVariable)
{
  auto result = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "MethodWithTypeDef"}, NodeClass::Method)
      .reference_type(NodeId{ReferenceTypeId::HasComponent})
      .requested_node_id(NodeId{mNamespaceIndex, uint32_t{9203}})
      // Set a non-null TypeDefinition - should be rejected for Method.
      .type_definition(NodeId{ObjectTypeId::BaseObjectType}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTypeDefinitionInvalid))
    << "TypeDefinition non-null for Method shall be rejected";
}

// Requirement: SVR-NM-AN-020 (SHALL return)
// Bad_ParentNodeIdInvalid - parent node does not exist.
// @relation(SVR-NM-AN-020, SVR-NM-SVC-002, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_020_BadParentNodeIdInvalid)
{
  auto result = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(NodeId{mNamespaceIndex, uint32_t{99999}},
        QualifiedName{mNamespaceIndex, "OrphanNode"},
        NodeClass::Variable)
      .reference_type(NodeId{ReferenceTypeId::HasComponent})
      .type_definition(NodeId{VariableTypeId::BaseDataVariableType}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadParentNodeIdInvalid))
    << "Non-existent parent shall return BadParentNodeIdInvalid";
}

// Requirement: SVR-NM-AN-021 (SHALL return)
// Bad_ReferenceTypeIdInvalid - invalid reference type.
// @relation(SVR-NM-AN-021, SVR-NM-SVC-002, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_021_BadReferenceTypeIdInvalid)
{
  AddNodesRequest req;
  auto item = make_add_variable(QualifiedName{mNamespaceIndex, "BadRefType"});
  item.reference_type_id() = NodeId{mNamespaceIndex, uint32_t{99998}};  // Non-existent ref type
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceTypeIdInvalid))
    << "Non-existent reference type shall return BadReferenceTypeIdInvalid";
}

// Requirement: SVR-NM-AN-024 (SHALL return)
// Bad_NodeIdExists - requested NodeId already in use.
// @relation(SVR-NM-AN-024, SVR-NM-SVC-002, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_024_BadNodeIdExists)
{
  // Use the parent folder's NodeId as the requested new NodeId.
  AddNodesRequest req;
  auto item = make_add_variable(QualifiedName{mNamespaceIndex, "Duplicate"}, mParentFolderId);
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdExists))
    << "Existing NodeId shall return BadNodeIdExists";
}

// Requirement: SVR-NM-AN-025 (SHALL return)
// Bad_NodeClassInvalid - invalid node class.
// @relation(SVR-NM-AN-025, SVR-NM-SVC-002, SVR-ADDRSP-005, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_025_BadNodeClassInvalid)
{
  auto result =
    mSession->node_management().try_add_nodes_sync(AddNodesBuilder()
                                                     .add_node(mParentFolderId,
                                                       QualifiedName{mNamespaceIndex, "BadNodeClass"},
                                                       NodeClass::Unspecified)  // Invalid
                                                     .reference_type(NodeId{ReferenceTypeId::HasComponent}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeClassInvalid))
    << "Unspecified node class shall return BadNodeClassInvalid";
}

// Requirement: SVR-NM-AN-026 (SHALL return)
// Bad_BrowseNameInvalid - empty/null browse name.
// @relation(SVR-NM-AN-026, SVR-NM-SVC-002, scope=function)
// @verifies AC-SVR-NM-AN-026-BROWSENAMEINVALID
TEST_F(ComplianceNodeManagement, NM_AN_026_BadBrowseNameInvalid)
{
  AddNodesRequest req;
  auto item = make_add_variable(QualifiedName{});  // Empty browse name
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadBrowseNameInvalid))
    << "Empty browse name shall return BadBrowseNameInvalid";
}

// Part 4 section 5.7.2.2 line 2644: "If the Node to add is a ReferenceType Node, its NodeId **should** be a
// numeric id." A recommendation rather than an obligation, and the criterion records it as one - so a
// failure here is advisory and would not be filed as a defect.
//
// The recommendation exists because ReferenceType ids travel in every Browse request a client makes:
// `referenceTypeId` is a parameter of BrowseDescription, and a numeric id encodes in four bytes where
// a string id encodes its whole length on every call. A server that allocates string ids for ReferenceTypes
// makes every subsequent browse fractionally more expensive for the life of the address space.
//
// The requested id is left null so the SERVER chooses, which is the only arrangement in which the
// recommendation is the server's to follow.
// @verifies AC-SVR-NM-AN-004-REFERENCETYPE-NUMERIC-ID
TEST_F(ComplianceNodeManagementAsConfigureAdmin, AServerAssignedReferenceTypeNodeIdIsNumeric)
{
  AddNodesItem item;
  item.parent_node_id() = ExpandedNodeId{NodeId{ReferenceTypeId::NonHierarchicalReferences}};
  item.reference_type_id() = NodeId{ReferenceTypeId::HasSubtype};
  item.requested_new_node_id() = ExpandedNodeId{};  // null: the server assigns.
  item.browse_name() = QualifiedName{mNamespaceIndex, "TestReferenceType"};
  item.node_class() = NodeClass::ReferenceType;

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(item));
  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good())
    << "the ReferenceType Node was not created, so no NodeId was assigned to inspect";

  const auto assigned = resp.results()[0].added_node_id();
  EXPECT_TRUE(assigned.is_numeric())
    << "the server assigned " << ua::to_string(assigned)
    << " to a ReferenceType. Part 4 section 5.7.2.2 recommends a numeric id, because this id travels in the "
       "referenceTypeId of every Browse a client makes and a string id pays its length on each one. "
       "This is a SHOULD: a failure here is advisory, not a defect";
}

// Requirement: SVR-NM-AN-027 (SHALL return)
// Bad_BrowseNameDuplicated - duplicate browse name under same parent.
// @relation(SVR-NM-AN-027, SVR-ADDRSP-007, SVR-ADDRSP-014, scope=function)
// @relation(AC-SVR-NM-AN-027-BROWSENAMEDUPLICATED, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_027_BadBrowseNameDuplicated)
{
  // First: add a node with a specific browse name.
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_variable(QualifiedName{mNamespaceIndex, "DupName"}, NodeId{mNamespaceIndex, uint32_t{9300}}));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(std::move(result).value().results()[0], Good());
  }

  // Second: try to add another node with the same browse name under the same parent.
  AddNodesRequest req;
  req.nodes_to_add().push_back(
    make_add_variable(QualifiedName{mNamespaceIndex, "DupName"}, NodeId{mNamespaceIndex, uint32_t{9301}}));
  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadBrowseNameDuplicated))
    << "Duplicate browse name under same parent shall return BadBrowseNameDuplicated";
}

// Requirement: SVR-NM-AN-029 (SHALL return)
// Bad_TypeDefinitionInvalid - non-existent type definition.
// Note: null TypeDefinition is valid - the server defaults to BaseObjectType/BaseDataVariableType
// per Part 4, section 5.7.2.2 (tested in NM_AN_006). This test uses a non-existent NodeId.
// @relation(SVR-NM-AN-029, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_029_BadTypeDefinitionInvalid)
{
  AddNodesRequest req;
  auto item =
    make_add_object(QualifiedName{mNamespaceIndex, "BadTypeDef"}, NodeId{mNamespaceIndex, uint32_t{9302}});
  item.type_definition() = ExpandedNodeId{NodeId{mNamespaceIndex, uint32_t{99999}}};
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTypeDefinitionInvalid))
    << "Non-existent type definition for Object shall return BadTypeDefinitionInvalid";
}

// ===========================================================================
// AddReferences - tests
// ===========================================================================

// Add a reference between existing nodes -> succeeds.
// @relation(SVR-NM-SVC-002, scope=function)
TEST_F(ComplianceNodeManagement, AddReferenceSuccess)
{
  // First create two nodes.
  auto sourceId = NodeId{mNamespaceIndex, uint32_t{9400}};
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9401}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "RefSource"}, sourceId));
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "RefTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 2u);
    ASSERT_THAT(resp.results()[0], Good());
    ASSERT_THAT(resp.results()[1], Good());
  }

  // Add a reference from source to target.
  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder().add_reference_async(sourceId, NodeId{ReferenceTypeId::Organizes}, targetId));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "AddReference between existing nodes should succeed";
}

// Add a reference, then verify it's visible in Browse results.
TEST_F(ComplianceNodeManagement, AddReferenceThenBrowse)
{
  auto sourceId = NodeId{mNamespaceIndex, uint32_t{9410}};
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9411}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_object(QualifiedName{mNamespaceIndex, "BrowseRefSource"}, sourceId));
    req.nodes_to_add().push_back(
      make_add_object(QualifiedName{mNamespaceIndex, "BrowseRefTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
  }

  // Add reference.
  {
    auto result = mSession->node_management().try_add_references_sync(
      AddReferencesBuilder().add_reference_async(sourceId, NodeId{ReferenceTypeId::HasComponent}, targetId));
    ASSERT_THAT(result, Good());
  }

  // Browse source -> should find target.
  auto browseResult = mSession->view().try_browse_sync(browse(sourceId));
  ASSERT_THAT(browseResult, Good());
  auto browseResp = std::move(browseResult).value();
  ASSERT_EQ(browseResp.results().size(), 1u);

  bool found = false;
  for (const auto& ref : browseResp.results()[0].references())
  {
    if (ref.node_id().node_id() == targetId)
    {
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found) << "Added reference should be visible in Browse results";
}

// Requirement: SVR-NM-AR-003 (SHALL)
// The source Node shall always exist.
// @relation(SVR-NM-AR-003, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_003_SourceMustExist)
{
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9420}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "ExistingTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
  }

  // Source exists (parent folder) -> should succeed.
  auto result =
    mSession->node_management().try_add_references_sync(AddReferencesBuilder().add_reference_async(
      mParentFolderId, NodeId{ReferenceTypeId::HasComponent}, targetId));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Existing source node should be accepted";
}

// Requirement: SVR-NM-AR-020 (SHALL return)
// Bad_SourceNodeIdInvalid - invalid source NodeId.
// @relation(SVR-NM-AR-003, SVR-NM-AR-020, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_020_BadSourceNodeIdInvalid)
{
  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder().add_reference_async(NodeId{mNamespaceIndex, uint32_t{99999}},  // Non-existent
      NodeId{ReferenceTypeId::HasComponent},
      mParentFolderId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadSourceNodeIdInvalid))
    << "Non-existent source shall return BadSourceNodeIdInvalid";
}

// Requirement: SVR-NM-AR-021 (SHALL return)
// Bad_ReferenceTypeIdInvalid - invalid reference type.
// @relation(SVR-NM-AR-021, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_021_BadReferenceTypeIdInvalid)
{
  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder().add_reference_async(mParentFolderId,
      NodeId{mNamespaceIndex, uint32_t{99998}},  // Non-existent
      mParentFolderId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceTypeIdInvalid))
    << "Non-existent reference type shall return BadReferenceTypeIdInvalid";
}

// Requirement: SVR-NM-AR-023 (SHALL return)
// Bad_TargetNodeIdInvalid - invalid target NodeId.
// @relation(SVR-NM-AR-023, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_023_BadTargetNodeIdInvalid)
{
  auto result =
    mSession->node_management().try_add_references_sync(AddReferencesBuilder().add_reference_async(
      mParentFolderId, NodeId{ReferenceTypeId::HasComponent}, NodeId{}));  // Null target
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTargetNodeIdInvalid))
    << "Null target shall return BadTargetNodeIdInvalid";
}

// Requirement: SVR-NM-AR-028 (SHALL return)
// Bad_DuplicateReferenceNotAllowed - duplicate reference.
// @relation(SVR-NM-AR-028, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_028_BadDuplicateReferenceNotAllowed)
{
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9430}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DupRefTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
  }

  // First add succeeds.
  {
    auto result =
      mSession->node_management().try_add_references_sync(AddReferencesBuilder().add_reference_async(
        mParentFolderId, NodeId{ReferenceTypeId::HasComponent}, targetId));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(std::move(result).value().results()[0], Good());
  }

  // Second add - duplicate.
  auto result =
    mSession->node_management().try_add_references_sync(AddReferencesBuilder().add_reference_async(
      mParentFolderId, NodeId{ReferenceTypeId::HasComponent}, targetId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadDuplicateReferenceNotAllowed))
    << "Duplicate reference shall return BadDuplicateReferenceNotAllowed";
}

// Part 4 section 5.7.3 with Part 3 section 5.3 - AddReferences supports the ReferenceTypes the data model
// defines, and HasSubtype between two ObjectTypes is the ordinary way a type hierarchy grows. The Node
// Management Add References conformance unit is MANDATORY in the Node Management 2022 Server Facet
// this product declares, so a HasSubtype the Server refuses for a reason the specification does not
// give is a conformance failure rather than a modelling preference.
//
// The plausible fault is not a missing check but an over-eager one. `ua_node_management_service.cpp`
// gives HasSubtype its own arm and authorises the item only when BOTH endpoints cast to
// `ReferenceTypeAccessor`, so that it can compare their Symmetric attributes. `NodeAccessor::as<T>()`
// returns nullopt unless the node's class matches (`ua_node_accessor.h:103-115`), and
// `ReferenceTypeAccessor::is_matching_class()` is `is_reference_type()`
// (`ua_node_accessor.cpp:298-301`) - so an ObjectType fails the cast, the conjunction collapses, and
// the item is answered Bad_ReferenceNotAllowed. A Symmetric comparison is meaningful only between
// ReferenceTypes; applying its precondition to every HasSubtype makes the ReferenceType case the only
// one the service can serve.
//
// Both endpoints are built server-side rather than through AddNodes, so that a refusal here is the
// AddReferences path's own and cannot be attributed to node creation.
// @verifies AC-SVR-NM-AR-025-REFERENCENOTALLOWED
TEST_F(ComplianceNodeManagement, HasSubtypeBetweenTwoObjectTypesIsAccepted)
{
  auto addressSpace = mServer->address_space();
  const auto baseTypeId = NodeId{mNamespaceIndex, uint32_t{9600}};
  const auto derivedTypeId = NodeId{mNamespaceIndex, uint32_t{9601}};

  const std::pair<NodeId, const char*> types[]{
    {baseTypeId, "SubtypeArmBaseType"}, {derivedTypeId, "SubtypeArmDerivedType"}};
  for (const auto& [id, name] : types)
  {
    auto node = addressSpace.create_node_sync(id, NodeClass::ObjectType);
    auto objectType = node.as<ObjectTypeAccessor>();
    ASSERT_TRUE(objectType.has_value()) << name << " was not created as an ObjectType";
    objectType->set_browse_name(QualifiedName{mNamespaceIndex, name});
    objectType->set_display_name(LocalizedText{"", String{name}});
    objectType->set_is_abstract(false);
  }
  addressSpace.find_node_sync(NodeId{ObjectTypeId::BaseObjectType})
    .add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, baseTypeId);

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(baseTypeId, NodeId{ReferenceTypeId::HasSubtype}, derivedTypeId)
      .target_node_class(NodeClass::ObjectType));
  ASSERT_THAT(result, Good()) << "AddReferences must not fail at the service interface";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good())
    << "a HasSubtype between two ObjectTypes was refused with status " << resp.results()[0].as_uint32()
    << ". Nothing in Part 3 forbids it and Part 4 Table 27 reserves Bad_ReferenceNotAllowed for a "
       "reference that violates the data model, so a client cannot extend a type hierarchy through "
       "the one Service the declared Node Management facet gives it for the purpose";
}

// ===========================================================================
// DeleteNodes - tests
// ===========================================================================

// Delete an existing node -> succeeds.
TEST_F(ComplianceNodeManagement, DeleteNodeSuccess)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9500}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_variable(QualifiedName{mNamespaceIndex, "ToDelete"}, nodeId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(std::move(result).value().results()[0], Good());
  }

  auto result = mSession->node_management().try_delete_nodes_sync(delete_node(nodeId));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Deleting existing node should succeed";
}

// Delete a node, then Read -> BadNodeIdUnknown.
TEST_F(ComplianceNodeManagement, DeleteNodeThenRead_Unknown)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9501}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_variable(QualifiedName{mNamespaceIndex, "ToDeleteRead"}, nodeId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(std::move(result).value().results()[0], Good());
  }

  // Delete.
  {
    auto result = mSession->node_management().try_delete_nodes_sync(delete_node(nodeId));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(std::move(result).value().results()[0], Good());
  }

  // Read the deleted node -> should fail.
  auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::BrowseName));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "Reading deleted node should fail with BadNodeIdUnknown";
}

// Requirement: SVR-NM-DN-021 (SHALL return)
// Bad_NodeIdUnknown - non-existent NodeId.
// @relation(SVR-NM-DN-021, scope=function)
TEST_F(ComplianceNodeManagement, NM_DN_021_BadNodeIdUnknown)
{
  auto result =
    mSession->node_management().try_delete_nodes_sync(delete_node(NodeId{mNamespaceIndex, uint32_t{99999}}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdUnknown))
    << "Non-existent node shall return BadNodeIdUnknown";
}

// ===========================================================================
// DeleteReferences - tests
// ===========================================================================

// Delete an existing reference -> succeeds.
// @relation(SVR-NM-DR-002, SVR-NM-SVC-002, scope=function)
TEST_F(ComplianceNodeManagement, DeleteReferenceSuccess)
{
  auto sourceId = NodeId{mNamespaceIndex, uint32_t{9600}};
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9601}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DelRefSource"}, sourceId));
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DelRefTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
  }
  {
    auto result = mSession->node_management().try_add_references_sync(
      AddReferencesBuilder().add_reference_async(sourceId, NodeId{ReferenceTypeId::HasComponent}, targetId));
    ASSERT_THAT(result, Good());
  }

  // Delete the reference.
  auto result = mSession->node_management().try_delete_references_sync(
    DeleteReferencesBuilder()
      .delete_reference(sourceId, NodeId{ReferenceTypeId::HasComponent}, targetId)
      .delete_bidirectional(false));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Deleting existing reference should succeed";
}

// Delete a reference, then verify it's gone from Browse results.
TEST_F(ComplianceNodeManagement, DeleteReferenceThenBrowse)
{
  auto sourceId = NodeId{mNamespaceIndex, uint32_t{9610}};
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9611}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_object(QualifiedName{mNamespaceIndex, "BrowseDelRefSrc"}, sourceId));
    req.nodes_to_add().push_back(
      make_add_object(QualifiedName{mNamespaceIndex, "BrowseDelRefTgt"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
  }
  {
    auto result = mSession->node_management().try_add_references_sync(
      AddReferencesBuilder().add_reference_async(sourceId, NodeId{ReferenceTypeId::HasComponent}, targetId));
    ASSERT_THAT(result, Good());
  }

  // Delete the reference.
  {
    auto result = mSession->node_management().try_delete_references_sync(
      DeleteReferencesBuilder()
        .delete_reference(sourceId, NodeId{ReferenceTypeId::HasComponent}, targetId)
        .delete_bidirectional(false));
    ASSERT_THAT(result, Good());
  }

  // Browse source -> target should NOT be found.
  auto browseResult = mSession->view().try_browse_sync(browse(sourceId));
  ASSERT_THAT(browseResult, Good());
  auto browseResp = std::move(browseResult).value();
  ASSERT_EQ(browseResp.results().size(), 1u);

  for (const auto& ref : browseResp.results()[0].references())
  {
    EXPECT_NE(ref.node_id().node_id(), targetId) << "Deleted reference should not appear in Browse results";
  }
}

// Requirement: SVR-NM-DR-020 (SHALL return)
// Bad_SourceNodeIdInvalid - invalid source.
// @relation(SVR-NM-DR-020, scope=function)
TEST_F(ComplianceNodeManagement, NM_DR_020_BadSourceNodeIdInvalid)
{
  auto result = mSession->node_management().try_delete_references_sync(
    DeleteReferencesBuilder()
      .delete_reference(NodeId{mNamespaceIndex, uint32_t{99999}},  // Non-existent
        NodeId{ReferenceTypeId::HasComponent},
        mParentFolderId)
      .delete_bidirectional(false));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadSourceNodeIdInvalid))
    << "Non-existent source shall return BadSourceNodeIdInvalid";
}

// Requirement: SVR-NM-DR-021 (SHALL return)
// Bad_ReferenceTypeIdInvalid - invalid reference type.
// @relation(SVR-NM-DR-021, scope=function)
TEST_F(ComplianceNodeManagement, NM_DR_021_BadReferenceTypeIdInvalid)
{
  auto result = mSession->node_management().try_delete_references_sync(
    DeleteReferencesBuilder()
      .delete_reference(mParentFolderId,
        NodeId{mNamespaceIndex, uint32_t{99998}},  // Non-existent
        mParentFolderId)
      .delete_bidirectional(false));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceTypeIdInvalid))
    << "Non-existent reference type shall return BadReferenceTypeIdInvalid";
}

// Requirement: SVR-NM-DR-023 (SHALL return)
// Bad_TargetNodeIdInvalid - invalid target.
// @relation(SVR-NM-DR-023, scope=function)
TEST_F(ComplianceNodeManagement, NM_DR_023_BadTargetNodeIdInvalid)
{
  auto result = mSession->node_management().try_delete_references_sync(
    DeleteReferencesBuilder()
      .delete_reference(mParentFolderId, NodeId{ReferenceTypeId::HasComponent}, NodeId{})  // Null target
      .delete_bidirectional(false));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTargetNodeIdInvalid))
    << "Null target shall return BadTargetNodeIdInvalid";
}

// ===========================================================================
// AddNodes - instantiation and default tests (document gaps)
// ===========================================================================

// Requirement: SVR-NM-AN-001 (SHALL)
// When a Node is added with a TypeDefinition, the Server shall instantiate mandatory children
// defined by ModellingRules in the TypeDefinition.
// Spec: Part 4, section 5.7.2.2
//
// This test creates an Object with TypeDefinition=FileType via AddNodes and then checks that
// mandatory children (Size, Open, Close, Read, Write) exist. The handler creates a bare node
// without instantiation, so this test documents the gap.
// @relation(SVR-NM-AN-001, SVR-ADDRSP-011, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_001_MandatoryChildrenCreated)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9700}};
  auto result = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "TestFile"}, NodeClass::Object)
      .reference_type(NodeId{ReferenceTypeId::Organizes})
      .requested_node_id(nodeId)
      .type_definition(NodeId{ObjectTypeId::FileType}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good()) << "AddNodes for FileType should succeed";

  // Browse the new node for mandatory children.
  auto browseResult = mSession->view().try_browse_sync(browse(nodeId));
  ASSERT_THAT(browseResult, Good());
  auto browseResp = std::move(browseResult).value();
  ASSERT_EQ(browseResp.results().size(), 1u);

  // FileType mandatory children include: Size, Open, Close, Read, Write.
  std::set<std::string> expectedChildren = {"Size", "Open", "Close", "Read", "Write"};
  std::set<std::string> foundChildren;
  for (const auto& ref : browseResp.results()[0].references())
  {
    std::string name = ref.browse_name().name();
    if (expectedChildren.count(name) > 0)
      foundChildren.insert(name);
  }

  // This asserts correct spec behavior. The handler does not instantiate, so this will fail.
  EXPECT_EQ(foundChildren, expectedChildren)
    << "All mandatory children of FileType shall be instantiated. " << "Found " << foundChildren.size()
    << " of " << expectedChildren.size();
}

// Requirement: SVR-NM-AN-002 (SHALL)
// All Nodes with a ModellingRule of Mandatory shall be created or an existing Node shall be
// referenced that conforms to the InstanceDeclaration.
// Spec: Part 4, section 5.7.2.1, line 2617
//
// Creates an Object with TypeDefinition=FileType. FileType defines mandatory children
// (Size, Open, Close, Read, Write, GetPosition, SetPosition) with Mandatory ModellingRule.
// The server shall create all of them. This is the same type as NM_AN_001 but focuses on
// the ModellingRule aspect: every Mandatory child must exist, Optional children may be absent.
// @relation(SVR-NM-AN-002, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_002_MandatoryModellingRuleCreated)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9710}};
  auto result = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "ModellingRuleFile"}, NodeClass::Object)
      .reference_type(NodeId{ReferenceTypeId::Organizes})
      .requested_node_id(nodeId)
      .type_definition(NodeId{ObjectTypeId::FileType}));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good()) << "AddNodes for FileType should succeed";

  // Browse the new node for children.
  auto browseResult = mSession->view().try_browse_sync(browse(nodeId));
  ASSERT_THAT(browseResult, Good());
  auto browseResp = std::move(browseResult).value();
  ASSERT_EQ(browseResp.results().size(), 1u);

  // FileType Mandatory children per ModellingRule: Size, Open, Close, Read, Write,
  // GetPosition, SetPosition. All have ModellingRule = Mandatory in the OPC UA spec.
  std::set<std::string> mandatoryChildren = {
    "Size", "Open", "Close", "Read", "Write", "GetPosition", "SetPosition"};
  std::set<std::string> foundChildren;
  for (const auto& ref : browseResp.results()[0].references())
  {
    std::string name = ref.browse_name().name();
    if (mandatoryChildren.count(name) > 0)
      foundChildren.insert(name);
  }

  EXPECT_EQ(foundChildren, mandatoryChildren)
    << "All Mandatory ModellingRule children of FileType shall be created. Found " << foundChildren.size()
    << " of " << mandatoryChildren.size();
}

// Requirement: SVR-NM-AN-005 (SHALL)
// If an Attribute value is null, the Server shall use the default values from the TypeDefinition.
// Spec: Part 4, section 5.7.2.2, line 2651
//
// Creates a Variable with TypeDefinition=BaseDataVariableType but null node_attributes.
// The server shall apply defaults from BaseDataVariableType: DataType should be set to
// BaseDataType (i=24), and ValueRank should be set to the type's default.
// The handler doesn't read defaults from the type definition, so this test documents the gap.
// @relation(SVR-NM-AN-005, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_005_NullAttributeUsesTypeDefault)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9720}};
  // node_attributes left empty/null - server shall use type defaults.
  auto result = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "NullAttrVar"}, NodeClass::Variable)
      .reference_type(NodeId{ReferenceTypeId::HasComponent})
      .requested_node_id(nodeId)
      .type_definition(NodeId{VariableTypeId::BaseDataVariableType}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good()) << "Null attributes with valid TypeDefinition should succeed";

  // Read the DataType attribute - should have been inherited from BaseDataVariableType.
  // BaseDataVariableType's DataType is BaseDataType (i=24).
  auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::DataType));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  ASSERT_THAT(readResp.results()[0], Good()) << "DataType attribute should be readable";
  // The DataType value should be BaseDataType (ns=0;i=24), inherited from the type definition.
  ASSERT_FALSE(readResp.results()[0].value().empty()) << "DataType should have a value";
  auto dataType = readResp.results()[0].value().as<NodeId>();
  EXPECT_EQ(dataType, NodeId(0u, uint32_t{24}))
    << "DataType shall default to BaseDataType (i=24) from the TypeDefinition";
}

// Part 4 section 5.7.2.2: when no TypeDefinitionNode exists, the Server chooses suitable Attribute
// defaults. The same clause requires TypeDefinition for Object and Variable, so this control uses a
// View, where the parameter is correctly null, and observes both mandatory View-specific defaults.
// @relation(AC-SVR-NM-AN-006-NO-TYPE-SUITABLE-DEFAULT, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_006_NoTypeDefServerChoosesDefault)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9730}};
  auto result = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "NoTypeDefView"}, NodeClass::View)
      .reference_type(NodeId{ReferenceTypeId::Organizes})
      .requested_node_id(nodeId)
      .type_definition(NodeId{}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good())
    << "a View correctly has no TypeDefinition and shall receive NodeClass defaults";

  auto containsNoLoops =
    mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::ContainsNoLoops));
  ASSERT_THAT(containsNoLoops, Good());
  ASSERT_EQ(containsNoLoops.value().results().size(), 1u);
  ASSERT_THAT(containsNoLoops.value().results()[0], Good());
  ASSERT_FALSE(containsNoLoops.value().results()[0].value().empty());
  EXPECT_FALSE(containsNoLoops.value().results()[0].value().as<bool>());

  auto eventNotifier = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::EventNotifier));
  ASSERT_THAT(eventNotifier, Good());
  ASSERT_EQ(eventNotifier.value().results().size(), 1u);
  ASSERT_THAT(eventNotifier.value().results()[0], Good());
  ASSERT_FALSE(eventNotifier.value().results()[0].value().empty());
  EXPECT_EQ(eventNotifier.value().results()[0].value().as<uint8_t>(), 0u);
}

// Requirement: SVR-NM-AN-023 (SHALL return)
// Bad_NodeIdRejected - the destination's identifier policy declines an otherwise valid requested id.
// Spec: Part 4, section 5.7.2.4
// @relation(SVR-NM-AN-023, SVR-NM-SVC-002, scope=function)
// @relation(AC-SVR-NM-AN-023-NODEIDREJECTED, scope=function)
TEST_F(ComplianceNodeManagement, NM_AN_023_BadNodeIdRejectedByDestinationPolicy)
{
  const NodeId rejectedId{mNamespaceIndex, uint32_t{99900}};
  mHandler->rejectedRequestedNodeIds.insert(rejectedId);

  AddNodesRequest req;
  auto item = make_add_variable(QualifiedName{mNamespaceIndex, "PolicyRejectedNode"});
  item.requested_new_node_id() = ExpandedNodeId{rejectedId};
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdRejected))
    << "the destination delegate's identifier policy shall be preserved";
}

// All registered namespaces use the same prepared-destination authorization and commit path. In
// particular, namespace zero is not globally reserved by AddNodes: its own permission answer and the
// installed delegate decide whether an item can be created there.
// @relation(AC-SVR-AUTHZ-003-NO-SPECIAL-NAMESPACE-BRANCH, scope=function)
TEST_F(ComplianceNodeManagementNamespaceParity, AuthorizedNamespaceZeroUsesTheOrdinaryAddNodesDelegateFlow)
{
  const NodeId requestedId{0, uint32_t{99901}};
  AddNodesRequest request;
  request.nodes_to_add().push_back(
    make_add_variable(QualifiedName{mNamespaceIndex, "AuthorizedNamespaceZeroNode"}, requestedId));
  auto result = mSession->node_management().try_add_nodes_sync(std::move(request));
  ASSERT_THAT(result, Good());
  auto response = std::move(result).value();
  ASSERT_EQ(response.results().size(), 1u);
  ASSERT_THAT(response.results()[0], Good());
  EXPECT_EQ(response.results()[0].added_node_id(), requestedId);
  EXPECT_TRUE(mServer->address_space().try_find_node_sync(requestedId).is_good());
}

// ===========================================================================
// DeleteNodes - additional requirement tests
// ===========================================================================

// Requirement: SVR-NM-DN-020 (SHALL return)
// Bad_NodeIdInvalid - null NodeId is invalid.
// Spec: Part 4, section 5.7.4
// @relation(SVR-NM-DN-020, SVR-NM-SVC-002, scope=function)
TEST_F(ComplianceNodeManagement, NM_DN_020_BadNodeIdInvalid)
{
  auto result = mSession->node_management().try_delete_nodes_sync(delete_node(NodeId{}));  // Null NodeId
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdInvalid))
    << "Null NodeId shall return BadNodeIdInvalid";
}

// Requirement: SVR-NM-DN-023 (SHALL return)
// Bad_NoDeleteRights - node is protected from deletion.
// Spec: Part 4, section 5.7.4
// @relation(SVR-NM-DN-023, scope=function)
TEST_F(ComplianceNodeManagement, NM_DN_023_BadNoDeleteRights)
{
  // Create a node, then protect it.
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9740}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_variable(QualifiedName{mNamespaceIndex, "ProtectedNode"}, nodeId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(std::move(result).value().results()[0], Good());
  }

  // Mark the node as protected.
  mHandler->protectedNodeIds.insert(nodeId);

  // Try to delete -> should fail with BadNoDeleteRights.
  auto result = mSession->node_management().try_delete_nodes_sync(delete_node(nodeId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNoDeleteRights))
    << "Protected node shall return BadNoDeleteRights";
}

// ===========================================================================
// AddReferences - additional requirement tests
// ===========================================================================

// Requirement: SVR-NM-AR-029 (SHALL return)
// Bad_InvalidSelfReference - source and target are the same node.
// Spec: Part 4, section 5.7.3
// @relation(SVR-NM-AR-029, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_029_BadInvalidSelfReference)
{
  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder().add_reference_async(mParentFolderId,
      NodeId{ReferenceTypeId::HasComponent},
      mParentFolderId));  // Same as source
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadInvalidSelfReference))
    << "Self-reference shall return BadInvalidSelfReference";
}

// Requirement: SVR-NM-AR-022 (SHALL return)
// Bad_ServerUriInvalid - non-empty target_server_uri that doesn't match the server.
// Spec: Part 4, section 5.7.3
// @relation(SVR-NM-AR-022, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_022_BadServerUriInvalid)
{
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9750}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_object(QualifiedName{mNamespaceIndex, "ServerUriTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
  }

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::HasComponent}, targetId)
      .target_server_uri("urn:some:unknown:server"));  // Non-empty, unknown URI
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadServerUriInvalid))
    << "Non-empty unknown target_server_uri shall return BadServerUriInvalid";
}

// Requirement: SVR-NM-AR-024 (SHALL return)
// Bad_NodeClassInvalid - target_node_class doesn't match actual node class.
// Spec: Part 4, section 5.7.3
// Covers SVR-NM-AR-002 (coverage-audit retag).
// @relation(SVR-NM-AR-002, SVR-NM-AR-004, SVR-NM-AR-024, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_024_BadNodeClassInvalid)
{
  // Create an Object node.
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9760}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_object(QualifiedName{mNamespaceIndex, "NodeClassTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    ASSERT_THAT(std::move(result).value().results()[0], Good());
  }

  // Add a reference with wrong target_node_class (Variable instead of Object).
  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::HasComponent}, targetId)
      .target_node_class(NodeClass::Variable));  // Wrong - node is actually Object
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeClassInvalid))
    << "Mismatched target_node_class shall return BadNodeClassInvalid";
}

// Requirement: SVR-NM-AR-025 (SHALL return)
// Bad_ReferenceNotAllowed - HasSubtype from a non-type node (Object).
// Spec: Part 4, section 5.7.3
// @relation(SVR-NM-AR-025, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_025_BadReferenceNotAllowed)
{
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9770}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "SubtypeTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
  }

  // Try to add HasSubtype from an Object (mParentFolderId is an Object, not a type node).
  auto result =
    mSession->node_management().try_add_references_sync(AddReferencesBuilder().add_reference_async(
      mParentFolderId, NodeId{ReferenceTypeId::HasSubtype}, targetId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceNotAllowed))
    << "HasSubtype from non-type node shall return BadReferenceNotAllowed";
}

// Requirement: SVR-NM-AR-026 (SHALL return)
// Bad_ReferenceLocalOnly - target with non-zero server_index.
// Spec: Part 4, section 5.7.3
// @relation(SVR-NM-AR-026, scope=function)
TEST_F(ComplianceNodeManagement, NM_AR_026_BadReferenceLocalOnly)
{
  ExpandedNodeId remoteTarget{NodeId{mNamespaceIndex, uint32_t{9780}}};
  remoteTarget.server_index() = 1;  // Non-zero - remote server

  AddReferencesRequest req;
  AddReferencesItem item;
  item.source_node_id() = mParentFolderId;
  item.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  item.is_forward() = true;
  item.target_node_id() = std::move(remoteTarget);
  item.target_node_class() = NodeClass::Object;
  req.references_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_references_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceLocalOnly))
    << "Non-zero server_index on target shall return BadReferenceLocalOnly";
}

// ===========================================================================
// DeleteReferences - additional requirement tests
// ===========================================================================

// Requirement: SVR-NM-DR-022 (SHALL return)
// Bad_ServerIndexInvalid - target_node_id with non-zero server_index.
// Spec: Part 4, section 5.7.5
// @relation(SVR-NM-DR-001, SVR-NM-DR-022, scope=function)
TEST_F(ComplianceNodeManagement, NM_DR_022_BadServerIndexInvalid)
{
  ExpandedNodeId remoteTarget{NodeId{mNamespaceIndex, uint32_t{9790}}};
  remoteTarget.server_index() = 1;  // Non-zero - invalid for local delete

  DeleteReferencesRequest req;
  DeleteReferencesItem item;
  item.source_node_id() = mParentFolderId;
  item.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  item.is_forward() = true;
  item.target_node_id() = std::move(remoteTarget);
  item.delete_bidirectional() = false;
  req.references_to_delete().push_back(std::move(item));

  auto result = mSession->node_management().try_delete_references_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadServerIndexInvalid))
    << "Non-zero server_index on target shall return BadServerIndexInvalid";
}

// Requirement: SVR-NM-DR-025 (SHALL return)
// Bad_NoDeleteRights - source node is protected from reference deletion.
// Spec: Part 4, section 5.7.5
// @relation(SVR-NM-DR-025, scope=function)
TEST_F(ComplianceNodeManagement, NM_DR_025_BadNoDeleteRights)
{
  // Create source and target nodes, add a reference, then protect the source.
  auto sourceId = NodeId{mNamespaceIndex, uint32_t{9800}};
  auto targetId = NodeId{mNamespaceIndex, uint32_t{9801}};
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "ProtRefSource"}, sourceId));
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "ProtRefTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
  }
  {
    auto result = mSession->node_management().try_add_references_sync(
      AddReferencesBuilder().add_reference_async(sourceId, NodeId{ReferenceTypeId::HasComponent}, targetId));
    ASSERT_THAT(result, Good());
  }

  // Protect the source node.
  mHandler->protectedNodeIds.insert(sourceId);

  // Try to delete the reference -> should fail.
  auto result = mSession->node_management().try_delete_references_sync(
    DeleteReferencesBuilder()
      .delete_reference(sourceId, NodeId{ReferenceTypeId::HasComponent}, targetId)
      .delete_bidirectional(false));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNoDeleteRights))
    << "Protected source shall return BadNoDeleteRights for reference deletion";
}

// ===========================================================================
// MonitoredItems - notification on delete (requires subscription infrastructure)
// ===========================================================================

// Requirement: SVR-NM-DN-002 (SHALL)
// When a Node is deleted, any MonitoredItems monitoring that Node shall receive a notification
// with BadNodeIdUnknown status.
// Spec: Part 4, section 5.7.4
//
// NOTE: This test is skipped because it requires subscription infrastructure (CreateSubscription,
// CreateMonitoredItems, Publish) which is not yet available in the test framework.
// TODO: Implement when subscription support is added.

// ===========================================================================
// Service-level tests
// ===========================================================================

// NodeManagement without handler -> BadServiceUnsupported.
TEST_F(ComplianceNodeManagement, BadServiceUnsupported_NoHandler)
{
  // Remove the handler.
  mServer->set_node_management_delegate(nullptr);

  AddNodesRequest req;
  req.nodes_to_add().push_back(make_add_variable(QualifiedName{mNamespaceIndex, "NoHandler"}));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  EXPECT_THAT(result, HasStatus(Status::BadServiceUnsupported))
    << "No handler shall return BadServiceUnsupported";
}

// ===========================================================================
// Row: ExecutionLimits::instantiationDepthLimit (configuration coverage matrix section 11).
//
// The budget on how far a single instantiation may descend through nested type structure. It is consumed
// by `InstantiationService` (`ua_instantiation_service.cpp:2052`), which this file's delegate drives for
// real on every AddNodes of an Object or Variable - so the stimulus arrives over the wire as a client
// AddNodes and the oracle is the per-operation status that client receives.
//
// A type with mandatory children is what makes the descent non-trivial: instantiating BaseObjectType alone
// would fit in any budget and the row would be vacuous whatever the limit.
// ===========================================================================
class ComplianceInstantiationDepth : public ComplianceNodeManagement
{
protected:
  void SetUp() override
  {
    mInstantiationDepthLimit = 100;  // default 10000; high enough for standard-model startup
    ComplianceNodeManagement::SetUp();
    mDeepTypeId = build_mandatory_object_chain(64);
  }

  NodeId mDeepTypeId;
};

// DEFAULT (10000): the same AddNodes descends the type's structure freely and succeeds.
TEST_F(ComplianceInstantiationDepth, DeepInstantiationIsRefusedWhenTheDepthBudgetIsExhausted)
{
  auto item = make_add_object(QualifiedName{mNamespaceIndex, "DepthProbe"});
  item.type_definition() = ExpandedNodeId{mDeepTypeId};

  AddNodesRequest request;
  request.nodes_to_add().push_back(std::move(item));
  auto result = mSession->node_management().try_add_nodes_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());

  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{Status::BadEncodingLimitsExceeded})
    << "a configured depth budget of 100 must refuse the 64-level mandatory declaration chain; "
       "under the default of 10000 this identical AddNodes succeeds";
}

// The control: the identical AddNodes on a server that left the budget at its default. Without this the
// row would pass against a build where instantiating FileDirectoryType fails for some unrelated reason.
TEST_F(ComplianceNodeManagement, DeepInstantiationSucceedsUnderTheDefaultDepthBudget)
{
  const NodeId deepTypeId = build_mandatory_object_chain(64);
  auto item = make_add_object(QualifiedName{mNamespaceIndex, "DepthControl"});
  item.type_definition() = ExpandedNodeId{deepTypeId};

  AddNodesRequest request;
  request.nodes_to_add().push_back(std::move(item));
  auto result = mSession->node_management().try_add_nodes_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());

  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_TRUE(result.value().results()[0].status_code().is_good())
    << "under the default instantiation budget the same AddNodes must succeed: "
    << to_string(result.value().results()[0].status_code());
}

// ===========================================================================
// AddNodes - obligations whose observable is derived from the address space
// rather than from a hard-coded expectation.
// ===========================================================================

// Part 4 section 5.7.2 / section 5.7.2.1: AddNodes with a typeDefinition is not a single Node creation - the
// server walks the TypeDefinitionNode's InstanceDeclaration tree and creates a child for every declaration
// carrying the Mandatory ModellingRule. A plausible implementation gets this wrong by creating the bare
// root Node and nothing else, or by creating a child whose NodeClass does not match the declaration
// (a Variable where the type declares a Method), which still browses as "a child of that name".
// The expectation here is read out of the type at run time, so it cannot drift from the type it checks.
// @relation(AC-SVR-NM-AN-001-INSTANCE-HIERARCHY-CREATED, scope=function)
// @relation(AC-SVR-ADDRSP-084-INSTANCE-MINIMUM-COMPONENTS, scope=function)
TEST_F(ComplianceNodeManagement, TheInstanceHierarchyTheTypeDeclaresIsCreatedBeneathTheNewNode)
{
  const auto typeId = NodeId{ObjectTypeId::FileType};

  // Derive the obligation from the type: every forward child of FileType that carries
  // HasModellingRule -> ModellingRule_Mandatory must exist beneath any instance of it.
  auto typeBrowse = mSession->view().try_browse_sync(browse(typeId));
  ASSERT_THAT(typeBrowse, Good());
  auto typeResp = std::move(typeBrowse).value();
  ASSERT_EQ(typeResp.results().size(), 1u);
  ASSERT_THAT(typeResp.results()[0], Good());
  ASSERT_FALSE(typeResp.results()[0].references().empty())
    << "FileType must expose its InstanceDeclarations, otherwise this test proves nothing";

  struct Declaration
  {
    std::string name;
    NodeClass nodeClass;
  };

  std::vector<Declaration> mandatory;

  for (const auto& typeRef : typeResp.results()[0].references())
  {
    if (!typeRef.is_forward())
      continue;
    if (typeRef.reference_type_id() == NodeId{ReferenceTypeId::HasSubtype})
      continue;  // A subtype of FileType is not an InstanceDeclaration of it.

    auto declBrowse = mSession->view().try_browse_sync(browse(typeRef.node_id().node_id()));
    ASSERT_THAT(declBrowse, Good()) << "browsing a candidate InstanceDeclaration failed for "
                                    << to_string(typeRef.node_id().node_id());
    auto declResp = std::move(declBrowse).value();
    ASSERT_EQ(declResp.results().size(), 1u)
      << "the candidate InstanceDeclaration browse returned no per-node result";
    ASSERT_THAT(declResp.results()[0], Good())
      << "browsing a candidate InstanceDeclaration failed for " << to_string(typeRef.node_id().node_id());

    for (const auto& declRef : declResp.results()[0].references())
    {
      if (declRef.reference_type_id() == NodeId{ReferenceTypeId::HasModellingRule} &&
          declRef.node_id().node_id() == NodeId{ObjectId::ModellingRule_Mandatory})
      {
        std::string declName = typeRef.browse_name().name();
        mandatory.push_back(Declaration{std::move(declName), typeRef.node_class()});
        break;
      }
    }
  }

  ASSERT_FALSE(mandatory.empty())
    << "FileType declares no Mandatory InstanceDeclaration - the hierarchy assertion below would be "
       "vacuous, so the address space, not the server's AddNodes, is at fault";

  // Now create an instance of exactly that type over the wire.
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9810}};
  auto addResult = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "DeclaredHierarchy"}, NodeClass::Object)
      .reference_type(NodeId{ReferenceTypeId::Organizes})
      .requested_node_id(nodeId)
      .type_definition(typeId));
  ASSERT_THAT(addResult, Good()) << "Service-level should succeed";
  auto addResp = std::move(addResult).value();
  ASSERT_EQ(addResp.results().size(), 1u);
  ASSERT_THAT(addResp.results()[0], Good()) << "AddNodes of a typed Object should succeed";

  auto instBrowse = mSession->view().try_browse_sync(browse(nodeId));
  ASSERT_THAT(instBrowse, Good());
  auto instResp = std::move(instBrowse).value();
  ASSERT_EQ(instResp.results().size(), 1u);
  ASSERT_THAT(instResp.results()[0], Good());
  ASSERT_FALSE(instResp.results()[0].references().empty())
    << "the new instance exposes no references at all - no hierarchy was created";

  for (const auto& decl : mandatory)
  {
    bool found = false;
    for (const auto& ref : instResp.results()[0].references())
    {
      if (!ref.is_forward())
        continue;
      std::string name = ref.browse_name().name();
      if (name == decl.name && ref.node_class() == decl.nodeClass)
      {
        found = true;
        break;
      }
    }
    EXPECT_TRUE(found) << "the type declares a Mandatory child '" << decl.name << "' of NodeClass "
                       << static_cast<uint32_t>(decl.nodeClass)
                       << "; the instance created by AddNodes has no such child";
  }
}

// Part 4 section 5.7.2.2: where there is no TypeDefinitionNode to take defaults from - which is every
// NodeClass other than Object and Variable - the server synthesises Attribute values suitable for the
// NodeClass rather than failing or leaving them absent. A plausible implementation creates the Node
// shell and stops, so the Node exists, browses, and yet a Read of the Attributes its NodeClass makes
// mandatory (Executable / UserExecutable on a Method) comes back Bad - a Node that exists and cannot
// be used. Both conjuncts are asserted: defaults present, and the Node readable.
// @verifies AC-SVR-NM-AN-006-NO-TYPE-SUITABLE-DEFAULT
TEST_F(ComplianceNodeManagement, AttributesAreGivenNodeClassDefaultsWhenNoTypeDefinitionIsSupplied)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9815}};

  // A Method takes no typeDefinition at all, so there is no type to inherit defaults from.
  auto addResult = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "NoTypeDefMethod"}, NodeClass::Method)
      .reference_type(NodeId{ReferenceTypeId::HasComponent})
      .requested_node_id(nodeId));
  ASSERT_THAT(addResult, Good()) << "Service-level should succeed";
  auto addResp = std::move(addResult).value();
  ASSERT_EQ(addResp.results().size(), 1u);
  ASSERT_THAT(addResp.results()[0], Good())
    << "a NodeClass that carries no typeDefinition shall be added, not refused";

  // The Node is readable: the Attributes every Node carries.
  auto browseNameRead = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::BrowseName));
  ASSERT_THAT(browseNameRead, Good());
  auto browseNameResp = std::move(browseNameRead).value();
  ASSERT_EQ(browseNameResp.results().size(), 1u);
  EXPECT_THAT(browseNameResp.results()[0], Good()) << "BrowseName shall be readable on the new Node";
  EXPECT_FALSE(browseNameResp.results()[0].value().empty()) << "BrowseName shall carry a value";

  auto displayNameRead = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::DisplayName));
  ASSERT_THAT(displayNameRead, Good());
  auto displayNameResp = std::move(displayNameRead).value();
  ASSERT_EQ(displayNameResp.results().size(), 1u);
  EXPECT_THAT(displayNameResp.results()[0], Good()) << "DisplayName shall be readable on the new Node";
  EXPECT_FALSE(displayNameResp.results()[0].value().empty()) << "DisplayName shall carry a value";

  // The Attributes the NodeClass makes mandatory, which only a per-NodeClass default table supplies.
  auto executableRead = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::Executable));
  ASSERT_THAT(executableRead, Good());
  auto executableResp = std::move(executableRead).value();
  ASSERT_EQ(executableResp.results().size(), 1u);
  EXPECT_THAT(executableResp.results()[0], Good())
    << "Executable is mandatory on a Method and shall be defaulted, not left absent";
  EXPECT_FALSE(executableResp.results()[0].value().empty())
    << "Executable shall carry a Boolean default rather than a null value";

  auto userExecutableRead =
    mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::UserExecutable));
  ASSERT_THAT(userExecutableRead, Good());
  auto userExecutableResp = std::move(userExecutableRead).value();
  ASSERT_EQ(userExecutableResp.results().size(), 1u);
  EXPECT_THAT(userExecutableResp.results()[0], Good())
    << "UserExecutable is mandatory on a Method and shall be defaulted, not left absent";
  EXPECT_FALSE(userExecutableResp.results()[0].value().empty())
    << "UserExecutable shall carry a Boolean default rather than a null value";

  // The synthesised defaults belong to the NodeClass that was asked for.
  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_FALSE(parentResp.results()[0].references().empty());

  bool found = false;
  for (const auto& ref : parentResp.results()[0].references())
  {
    if (ref.node_id().node_id() != nodeId)
      continue;
    found = true;
    EXPECT_EQ(ref.node_class(), NodeClass::Method)
      << "the Node shall be created with the NodeClass the client asked for";
  }
  EXPECT_TRUE(found) << "the new Node shall be attached beneath its parent";
}

// Part 4 section 5.7.2.4: Bad_ReferenceTypeIdInvalid is returned when the attaching referenceTypeId does not
// resolve to a ReferenceType Node. A plausible implementation only checks that the id resolves to
// *something* - which lets an ObjectType id through and attaches the new Node by a "reference type"
// that no Browse filter can ever match, i.e. an unreachable Node. Distinct from AC-SVR-NM-AN-022:
// here the id names the wrong kind of Node, not a valid ReferenceType the model forbids in this place.
// @relation(AC-SVR-NM-AN-021-REFERENCETYPEIDINVALID, scope=function)
TEST_F(ComplianceNodeManagement, AnAttachingReferenceTypeThatIsNotAReferenceTypeIsRefused)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9820}};
  AddNodesRequest req;
  auto item = make_add_variable(QualifiedName{mNamespaceIndex, "NotAReferenceType"}, nodeId);
  // BaseObjectType exists, so an existence check passes - but it is an ObjectType, not a ReferenceType.
  item.reference_type_id() = NodeId{ObjectTypeId::BaseObjectType};
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceTypeIdInvalid))
    << "a referenceTypeId naming a Node that is not a ReferenceType shall return "
       "BadReferenceTypeIdInvalid";
}

// Part 4 section 5.7.2.4: Bad_ReferenceNotAllowed is returned when the attaching reference is a valid
// ReferenceType but one the data model does not permit between those two NodeClasses - HasSubtype
// from an Object here. This is the code that keeps the address space well-formed under client edits;
// a plausible implementation validates only that the ReferenceType resolves and then creates the Node
// anyway, leaving a Node behind that is attached by a reference the model forbids. Both conjuncts are
// asserted: the status code, and that nothing was created at the requested NodeId.
// @relation(AC-SVR-NM-AN-022-REFERENCENOTALLOWED, scope=function)
TEST_F(ComplianceNodeManagement, AReferenceTheDataModelForbidsIsRefusedAndNoNodeIsCreated)
{
  auto nodeId = NodeId{mNamespaceIndex, uint32_t{9830}};

  // mParentFolderId is an Object; HasSubtype is only defined between type Nodes.
  auto result = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "ForbiddenAttach"}, NodeClass::Object)
      .reference_type(NodeId{ReferenceTypeId::HasSubtype})
      .requested_node_id(nodeId)
      .type_definition(NodeId{ObjectTypeId::BaseObjectType}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceNotAllowed))
    << "HasSubtype from an Object parent shall return BadReferenceNotAllowed";

  // Second conjunct: the refusal left nothing behind.
  auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::BrowseName));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a refused AddNodes shall create no Node at the requested NodeId";
}

// Part 4 section 5.7.2.4: Bad_NodeIdExists is returned when the requestedNewNodeId is a valid, allowed id
// that another Node already holds. The refusal is not the whole obligation - the existing Node must
// also survive intact. Treating AddNodes as an upsert is the plausible shortcut, and it is the
// dangerous one: the incumbent's references and subscriptions would survive pointing at different
// content, so the second conjunct (the incumbent is untouched) is asserted alongside the status.
// The refusal here originates in the address space itself (`default_ns::Namespace::create_node`
// raises Bad_NodeIdExists on a duplicate id), so the delegate only conducts it.
// @verifies AC-SVR-NM-AN-024-NODEIDEXISTS
TEST_F(ComplianceNodeManagement, AddingANodeUnderAnIdAlreadyInUseIsRefusedAndLeavesTheIncumbentIntact)
{
  const auto occupiedId = NodeId{mNamespaceIndex, uint32_t{9840}};
  const auto incumbentName = QualifiedName{mNamespaceIndex, "IncumbentNode"};

  // The incumbent is created over the wire by the same service, so the id really is in use.
  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(make_add_object(incumbentName, occupiedId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "the incumbent must be created, or this test proves nothing";
    ASSERT_EQ(resp.results()[0].added_node_id(), occupiedId);
  }

  // A different NodeClass, a different browse name - only the requested NodeId collides, so nothing
  // but the id-in-use condition can account for the refusal.
  AddNodesRequest req;
  req.nodes_to_add().push_back(make_add_variable(QualifiedName{mNamespaceIndex, "UsurperNode"}, occupiedId));
  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdExists))
    << "a requestedNewNodeId another Node already holds shall return BadNodeIdExists, got "
    << to_string(resp.results()[0].status_code());

  // Second conjunct: the incumbent is untouched. Its Attributes still read, and they still describe
  // the Node that was there first rather than the one the refused request asked for.
  auto readResult = mSession->attributes().try_read_sync(read_value(occupiedId, AttributeId::BrowseName));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], Good()) << "the existing Node shall still be readable";
  EXPECT_FALSE(readResp.results()[0].value().empty()) << "the existing Node shall still carry a BrowseName";

  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no children at all - the incumbent assertions below would be vacuous";

  bool incumbentFound = false;
  for (const auto& ref : parentResp.results()[0].references())
  {
    if (ref.node_id().node_id() != occupiedId)
      continue;
    incumbentFound = true;
    std::string name = ref.browse_name().name();
    std::string expectedName = incumbentName.name();
    EXPECT_EQ(name, expectedName) << "the refused AddNodes shall not rename the Node already holding that id";
    EXPECT_EQ(ref.node_class(), NodeClass::Object)
      << "the refused AddNodes shall not change the NodeClass of the Node already holding that id";
  }
  EXPECT_TRUE(incumbentFound) << "the Node that held the id shall still be attached beneath its parent";

  for (const auto& ref : parentResp.results()[0].references())
  {
    std::string name = ref.browse_name().name();
    EXPECT_NE(name, std::string{"UsurperNode"}) << "a refused AddNodes shall leave no Node behind";
  }
}

// ===========================================================================
// AddNodes - obligations the SDK owes on the request parameters themselves.
//
// SVR-NM-AN-003, -008 and -023 constrain the AddNodes *parameters* (serverIndex, the
// typeDefinition/NodeClass pairing, and which requested NodeIds a server will assign), and their
// DESIGN_COVERAGE places every one of them in the SDK's own validation ahead of the delegate -
// `NodeManagementHandler::validate_requested_node_id`, `validate_type_definition_presence`, and the
// `NodeManagementService` requested-NodeId policy check respectively.
//
// `BasicNodeManagementDelegate` above happens to re-implement all three itself, so a test run
// against it observes the delegate's own `if`, not the server's validation, and would pass on a
// server that performs none. The delegate below therefore applies no parameter policy of its own: it
// creates whatever it is handed. Since `NodeManagementService::start_add_nodes_handler_call` only
// dispatches items that survived its own validation, and the delegate's per-item status is copied
// straight through, any refusal a test on this fixture observes can only have come from the SDK or
// from the address space.
// ===========================================================================

class PermissiveNodeManagementDelegate final : public NodeManagementDelegate
{
public:
  void reject_requested_node_id(NodeId nodeId)
  {
    mRejectedRequestedNodeIds.insert(std::move(nodeId));
  }

  void prepare_add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context>, AddressSpace,
    std::vector<AddNodesItem> items,
    NodeManagementDelegate::PrepareAddNodesCallback callback) noexcept override
  {
    prepare_add_nodes_in_requested_or_parent_namespace(std::move(items), std::move(callback));
  }

  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    batch.items.reserve(items.size());

    for (auto& authorizedItem : items)
    {
      auto& item = authorizedItem.item;
      AddNodesResult result;
      try
      {
        auto parentId = item.parent_node_id().node_id();
        auto parentResult = addressSpace.try_find_node_sync(parentId);
        if (parentResult.is_bad())
        {
          result.status_code() = Status::BadParentNodeIdInvalid;
          batch.items.emplace_back(std::move(result));
          continue;
        }

        // No serverIndex check, no namespace policy, no typeDefinition/NodeClass check: whatever the
        // client asked for is what gets created.
        auto requestedId = item.requested_new_node_id().node_id();
        if (requestedId.is_null())
          requestedId = NodeId{authorizedItem.destination.namespaceIndex, ++mNextNodeId};
        if (mRejectedRequestedNodeIds.contains(requestedId))
        {
          result.status_code() = Status::BadNodeIdRejected;
          batch.items.emplace_back(std::move(result));
          continue;
        }

        auto createResult = addressSpace.try_create_node_sync(requestedId, item.node_class(), {});
        if (createResult.is_bad())
        {
          result.status_code() = createResult.status_code().as_status();
          batch.items.emplace_back(std::move(result));
          continue;
        }

        auto node = createResult.value();
        node.set_browse_name(item.browse_name());
        node.set_display_name(LocalizedText{"", String{item.browse_name().name()}});

        auto parent = parentResult.value();
        parent.try_add_reference_sync(item.reference_type_id(), requestedId);

        result.status_code() = Status::Good;
        result.added_node_id() = requestedId;
      }
      catch (const UaException& ex)
      {
        result.status_code() = ex.status();
      }
      catch (...)
      {
        result.status_code() = Status::BadInternalError;
      }
      batch.items.emplace_back(std::move(result));
    }

    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<AddReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    callback(unsupported(items.size()));
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteNodesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    callback(unsupported(items.size()));
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    callback(unsupported(items.size()));
  }

private:
  /// The tests on this fixture only exercise AddNodes; the other operations are not implemented.
  static BatchResult<VoidResult> unsupported(std::size_t count)
  {
    BatchResult<VoidResult> batch;
    batch.items.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
      batch.items.emplace_back(VoidResult{StatusCode{Status::BadServiceUnsupported}});
    }
    return batch;
  }

  uint32_t mNextNodeId{60000};
  std::unordered_set<NodeId> mRejectedRequestedNodeIds;
};

class ComplianceAddNodesParameterValidation : public ComplianceNodeManagement
{
protected:
  void SetUp() override
  {
    ComplianceNodeManagement::SetUp();
    ASSERT_TRUE(mServer.has_value());
    mPermissiveHandler = std::make_shared<PermissiveNodeManagementDelegate>();
    mServer->set_node_management_delegate(ua::test::offloaded(mPermissiveHandler));
  }

  std::shared_ptr<PermissiveNodeManagementDelegate> mPermissiveHandler;
};

// Part 4 section 5.7.2: the serverIndex of requestedNewNodeId shall be zero, because AddNodes only ever
// creates Nodes in the local address space. A plausible implementation reads through to the inner
// NodeId and ignores the serverIndex entirely - which is worse than silently dropping the request,
// because it leaves a local Node under an id that, as written, denotes a Node on another server.
// Both halves of that harm are asserted: the operation is refused, and nothing is created at the
// local projection of the id.
// The SDK screen runs before the application delegate; the readback proves the rejected expanded id
// was not projected into the local address space.
// @relation(AC-SVR-NM-AN-003-SERVERINDEX-ZERO, scope=function)
TEST_F(ComplianceAddNodesParameterValidation, ARequestedNewNodeIdWithANonZeroServerIndexIsRefused)
{
  const auto localProjection = NodeId{mNamespaceIndex, uint32_t{9850}};

  AddNodesItem item;
  item.parent_node_id() = ExpandedNodeId{mParentFolderId};
  item.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  ExpandedNodeId requested{localProjection};
  requested.server_index() = 1;  // Names another server's address space.
  item.requested_new_node_id() = std::move(requested);
  item.browse_name() = QualifiedName{mNamespaceIndex, "ForeignServerIndex"};
  item.node_class() = NodeClass::Variable;
  item.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(item));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_TRUE(resp.results()[0].status_code().is_bad())
    << "a requestedNewNodeId whose serverIndex is not zero asks this server to create a Node in "
       "another server's address space and shall be refused; got "
    << to_string(resp.results()[0].status_code());

  // The refusal is only meaningful if no Node was left behind under the id's local projection.
  auto readResult =
    mSession->attributes().try_read_sync(read_value(localProjection, AttributeId::BrowseName));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "no local Node shall be created under an id whose serverIndex denotes another server";
}

// Part 4 section 5.7.2: typeDefinition is the source of a HasTypeDefinition reference, and only Objects and
// Variables may be the source of one - so the parameter is required for exactly those two
// NodeClasses and must be absent for every other. A plausible implementation treats the parameter as
// advisory in both directions: it ignores a typeDefinition supplied on a Method (leaving a Node whose
// NodeClass forbids the reference that parameter asks for), and quietly substitutes BaseObjectType
// when an Object supplies none. Both stimuli are driven and both refusals are asserted.
//
// SVR-NM-AN-006 does not soften the second item: it scopes itself to "NodeClasses where
// typeDefinition is null (per SVR-NM-AN-008: anything other than Object/Variable)", so the default
// it permits is a default for attributes of a Method or a View, never a substitute typeDefinition
// for an Object. SVR-NM-AN-008 states the code the two refusals carry: Bad_TypeDefinitionInvalid.
// The SDK screens both directions before authorization and delegate dispatch; the readbacks below
// prove the refusals are non-mutating.
// @relation(AC-SVR-NM-AN-008-TYPEDEFINITION-SCOPE, scope=function)
// clang-format off
TEST_F(ComplianceAddNodesParameterValidation, TypeDefinitionIsRequiredForObjectsAndVariablesAndForbiddenElsewhere)
// clang-format on
{
  const auto methodId = NodeId{mNamespaceIndex, uint32_t{9860}};
  const auto objectId = NodeId{mNamespaceIndex, uint32_t{9861}};

  // A Method can never be the source of a HasTypeDefinition, so supplying one is a parameter error.
  AddNodesItem method;
  method.parent_node_id() = ExpandedNodeId{mParentFolderId};
  method.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  method.requested_new_node_id() = ExpandedNodeId{methodId};
  method.browse_name() = QualifiedName{mNamespaceIndex, "MethodWithATypeDefinition"};
  method.node_class() = NodeClass::Method;
  method.type_definition() = ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}};

  // An Object must always be the source of one, so omitting it is a parameter error.
  AddNodesItem object;
  object.parent_node_id() = ExpandedNodeId{mParentFolderId};
  object.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  object.requested_new_node_id() = ExpandedNodeId{objectId};
  object.browse_name() = QualifiedName{mNamespaceIndex, "ObjectWithoutATypeDefinition"};
  object.node_class() = NodeClass::Object;
  object.type_definition() = ExpandedNodeId{NodeId{}};

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(method));
  req.nodes_to_add().push_back(std::move(object));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTypeDefinitionInvalid))
    << "a typeDefinition supplied for a NodeClass that cannot be the source of a HasTypeDefinition "
       "shall be refused; got "
    << to_string(resp.results()[0].status_code());
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadTypeDefinitionInvalid))
    << "an Object supplying no typeDefinition shall be refused; got "
    << to_string(resp.results()[1].status_code());

  // Neither refusal shall leave a Node behind.
  auto methodRead = mSession->attributes().try_read_sync(read_value(methodId, AttributeId::BrowseName));
  ASSERT_THAT(methodRead, Good());
  auto methodResp = std::move(methodRead).value();
  ASSERT_EQ(methodResp.results().size(), 1u);
  EXPECT_THAT(methodResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "the refused Method shall not exist";

  auto objectRead = mSession->attributes().try_read_sync(read_value(objectId, AttributeId::BrowseName));
  ASSERT_THAT(objectRead, Good());
  auto objectResp = std::move(objectRead).value();
  ASSERT_EQ(objectResp.results().size(), 1u);
  EXPECT_THAT(objectResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "the refused Object shall not exist";
}

// Part 4 section 5.7.2.4: Bad_NodeIdRejected covers both an invalid id and an id the destination policy will
// not assign. Namespace identification owns the malformed arm; the mutation delegate owns the policy
// arm after destination authorization. The occupied control pins BadNodeIdExists as a distinct result.
// @relation(AC-SVR-NM-AN-023-NODEIDREJECTED, scope=function)
TEST_F(ComplianceAddNodesParameterValidation,
  ARequestedNodeIdThatIsInvalidOrUnassignableIsRejectedDistinctlyFromOneInUse)
{
  // (a) Malformed: a namespace index the server's NamespaceArray does not contain, so the id cannot
  //     denote anything this server is able to create.
  AddNodesItem malformed;
  malformed.parent_node_id() = ExpandedNodeId{mParentFolderId};
  malformed.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  malformed.requested_new_node_id() = ExpandedNodeId{NodeId{uint16_t{250}, uint32_t{9870}}};
  malformed.browse_name() = QualifiedName{mNamespaceIndex, "UnknownNamespaceId"};
  malformed.node_class() = NodeClass::Variable;
  malformed.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};

  // (b) Well-formed but declined by this destination's application policy.
  const NodeId policyRejectedId{mNamespaceIndex, uint32_t{9871}};
  mPermissiveHandler->reject_requested_node_id(policyRejectedId);
  AddNodesItem policyRejected;
  policyRejected.parent_node_id() = ExpandedNodeId{mParentFolderId};
  policyRejected.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  policyRejected.requested_new_node_id() = ExpandedNodeId{policyRejectedId};
  policyRejected.browse_name() = QualifiedName{mNamespaceIndex, "PolicyRejectedId"};
  policyRejected.node_class() = NodeClass::Variable;
  policyRejected.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};

  // (c) The contrast: a valid, allowed id that is simply already in use.
  AddNodesItem inUse;
  inUse.parent_node_id() = ExpandedNodeId{mParentFolderId};
  inUse.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  inUse.requested_new_node_id() = ExpandedNodeId{mParentFolderId};
  inUse.browse_name() = QualifiedName{mNamespaceIndex, "AlreadyTakenId"};
  inUse.node_class() = NodeClass::Variable;
  inUse.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(malformed));
  req.nodes_to_add().push_back(std::move(policyRejected));
  req.nodes_to_add().push_back(std::move(inUse));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 3u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdRejected))
    << "a requestedNewNodeId in a namespace the server does not have shall return BadNodeIdRejected; "
       "got "
    << to_string(resp.results()[0].status_code());
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadNodeIdRejected))
    << "a requestedNewNodeId the server will not assign shall return BadNodeIdRejected; got "
    << to_string(resp.results()[1].status_code());
  EXPECT_THAT(resp.results()[2], HasStatus(Status::BadNodeIdExists))
    << "an id that is merely already in use shall be reported distinctly from one that is rejected; "
       "got "
    << to_string(resp.results()[2].status_code());

  // The policy refusal is only meaningful if the delegate did not create the rejected Node.
  auto rejectedRead =
    mSession->attributes().try_read_sync(read_value(policyRejectedId, AttributeId::BrowseName));
  ASSERT_THAT(rejectedRead, Good());
  auto rejectedResponse = std::move(rejectedRead).value();
  ASSERT_EQ(rejectedResponse.results().size(), 1u);
  EXPECT_THAT(rejectedResponse.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a policy-rejected requestedNewNodeId shall leave no Node behind";
}

// Part 4 section 5.7.2.4: every AddNodes item shall carry a well-formed browseName - a non-empty name part,
// in a namespace index the server actually has - and Bad_BrowseNameInvalid is the operation-level code
// when it does not. A plausible implementation treats browseName as opaque application data and stores
// whatever arrives, which is how both stimuli below cause lasting damage: an empty name gives the
// address space a Node that no BrowsePath element can ever select, and a name qualified by a namespace
// index absent from the NamespaceArray gives it a Node whose name denotes nothing this server can
// resolve. Both stimuli are driven in one request and both refusals are asserted, and neither refusal
// may leave a Node behind at the id it asked for. The fixture's delegate applies no browseName policy
// of its own, so any refusal observed here can only have come from the SDK.
// @verifies AC-SVR-NM-AN-026-BROWSENAMEINVALID
TEST_F(ComplianceAddNodesParameterValidation, AnAddNodesItemWhoseBrowseNameIsNotWellFormedIsRefused)
{
  const auto emptyNameId = NodeId{mNamespaceIndex, uint32_t{9880}};
  const auto unknownNamespaceNameId = NodeId{mNamespaceIndex, uint32_t{9881}};

  // (a) No name part at all: the Node would be unreachable by name.
  AddNodesItem emptyName;
  emptyName.parent_node_id() = ExpandedNodeId{mParentFolderId};
  emptyName.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  emptyName.requested_new_node_id() = ExpandedNodeId{emptyNameId};
  emptyName.browse_name() = QualifiedName{};
  emptyName.node_class() = NodeClass::Variable;
  emptyName.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};

  // (b) A name part, but qualified by a namespace index the server's NamespaceArray does not contain.
  //     Only the browseName is at fault here: the requested NodeId is in the test namespace.
  AddNodesItem unknownNamespaceName;
  unknownNamespaceName.parent_node_id() = ExpandedNodeId{mParentFolderId};
  unknownNamespaceName.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  unknownNamespaceName.requested_new_node_id() = ExpandedNodeId{unknownNamespaceNameId};
  unknownNamespaceName.browse_name() = QualifiedName{uint16_t{250}, "UnknownNamespaceBrowseName"};
  unknownNamespaceName.node_class() = NodeClass::Variable;
  unknownNamespaceName.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(emptyName));
  req.nodes_to_add().push_back(std::move(unknownNamespaceName));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadBrowseNameInvalid))
    << "an AddNodes item with an empty browseName shall return BadBrowseNameInvalid; got "
    << to_string(resp.results()[0].status_code());
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadBrowseNameInvalid))
    << "an AddNodes item whose browseName names a namespace index the server does not have shall "
       "return BadBrowseNameInvalid; got "
    << to_string(resp.results()[1].status_code());

  // Each refusal is only meaningful if it created nothing at the id the refused item asked for.
  auto emptyNameRead = mSession->attributes().try_read_sync(read_value(emptyNameId, AttributeId::BrowseName));
  ASSERT_THAT(emptyNameRead, Good());
  auto emptyNameResp = std::move(emptyNameRead).value();
  ASSERT_EQ(emptyNameResp.results().size(), 1u);
  EXPECT_THAT(emptyNameResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a Node refused for an empty browseName shall not exist";

  auto unknownNamespaceRead =
    mSession->attributes().try_read_sync(read_value(unknownNamespaceNameId, AttributeId::BrowseName));
  ASSERT_THAT(unknownNamespaceRead, Good());
  auto unknownNamespaceResp = std::move(unknownNamespaceRead).value();
  ASSERT_EQ(unknownNamespaceResp.results().size(), 1u);
  EXPECT_THAT(unknownNamespaceResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a Node refused for a browseName in an unknown namespace shall not exist";
}

// Part 4 section 5.7.2.2: the server MAY add an Optional Attribute the Client did not specify, but a licence
// to add it is not a licence to add it empty - permission attaches to "with an appropriate default
// value". A plausible implementation reserves a slot for every Attribute the NodeClass allows and
// answers Read out of that slot whether or not anything was ever put in it, which reports Good and
// hands the client nothing to decode: strictly worse than omitting the Attribute, because the client
// is told the Attribute exists. The permitted alternative - not adding it at all, so the Read is Bad -
// is accepted here, since the criterion observes the shape of the choice rather than forcing it. The
// mandatory Attributes are read first so a Bad on an Optional one means "not added" rather than "this
// Node cannot be read"; without that, every Optional branch could pass for the wrong reason.
// @verifies AC-SVR-NM-AN-007-OPTIONAL-ATTRIBUTE-ADDED
TEST_F(ComplianceNodeManagement, AnOptionalAttributeTheClientOmittedIsEitherAbsentOrCarriesADefault)
{
  const auto nodeId = NodeId{mNamespaceIndex, uint32_t{9890}};

  // No node attributes are supplied at all, so every Optional Attribute examined below is one the
  // client omitted and the server was free either to add or to leave out.
  AddNodesRequest req;
  req.nodes_to_add().push_back(make_add_variable(QualifiedName{mNamespaceIndex, "OmittedOptionals"}, nodeId));
  auto addResult = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(addResult, Good()) << "Service-level should succeed";
  auto addResp = std::move(addResult).value();
  ASSERT_EQ(addResp.results().size(), 1u);
  ASSERT_THAT(addResp.results()[0], Good()) << "the Node must be created, or this test proves nothing";
  ASSERT_EQ(addResp.results()[0].added_node_id(), nodeId);

  // The Attributes every Node carries, whatever its NodeClass: these establish that Reads against
  // this Node resolve at all.
  auto browseNameRead = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::BrowseName));
  ASSERT_THAT(browseNameRead, Good());
  auto browseNameResp = std::move(browseNameRead).value();
  ASSERT_EQ(browseNameResp.results().size(), 1u);
  ASSERT_THAT(browseNameResp.results()[0], Good()) << "the new Node shall be readable";
  ASSERT_FALSE(browseNameResp.results()[0].value().empty()) << "BrowseName shall carry a value";

  auto displayNameRead = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::DisplayName));
  ASSERT_THAT(displayNameRead, Good());
  auto displayNameResp = std::move(displayNameRead).value();
  ASSERT_EQ(displayNameResp.results().size(), 1u);
  ASSERT_THAT(displayNameResp.results()[0], Good()) << "the new Node shall be readable";
  ASSERT_FALSE(displayNameResp.results()[0].value().empty()) << "DisplayName shall carry a value";

  struct OptionalAttribute
  {
    AttributeId id;
    const char* name;
  };

  // Optional on a Variable per Part 3 section 5.6 - the client specified a value for none of them.
  const std::vector<OptionalAttribute> optionalAttributes = {{AttributeId::Description, "Description"},
    {AttributeId::WriteMask, "WriteMask"},
    {AttributeId::UserWriteMask, "UserWriteMask"},
    {AttributeId::MinimumSamplingInterval, "MinimumSamplingInterval"}};
  ASSERT_FALSE(optionalAttributes.empty()) << "no Optional Attribute is examined - the loop is vacuous";

  for (const auto& attribute : optionalAttributes)
  {
    SCOPED_TRACE(attribute.name);

    auto attributeRead = mSession->attributes().try_read_sync(read_value(nodeId, attribute.id));
    ASSERT_THAT(attributeRead, Good()) << "Service-level should succeed";
    auto attributeResp = std::move(attributeRead).value();
    ASSERT_EQ(attributeResp.results().size(), 1u);

    const auto attributeStatus = attributeResp.results()[0].status().value_or(StatusCode{Status::Good});
    if (attributeStatus.is_bad())
      continue;  // permitted: the server chose not to add this Optional Attribute.

    EXPECT_FALSE(attributeResp.results()[0].value().empty())
      << "the server added the Optional Attribute " << attribute.name
      << " and then reported it Good with no value; the permission in Part 4 section 5.7.2.2 is to add it "
         "with an appropriate default, so an empty Attribute is not one of the two allowed outcomes";
  }
}

// Part 4 section 5.7.2.4: Bad_BrowseNameDuplicated is the operation-level code when the new Node's
// browseName is not unique among the Nodes sharing the same relationship with the parent. The model
// rule that makes a name non-unique is Part 3 section 5.6.3 - "It is not permitted for a Node to refer to
// two Variables using HasProperty References having the same BrowseName" - so the collision is
// staged on HasProperty, where a duplicate is forbidden outright. It is not staged on HasComponent:
// Part 3 section 4.5.4 confines BrowseName uniqueness to TypeDefinitionNodes and InstanceDeclarations -
// "not for other instances" - and this fixture's parent is a plain Object with no type definition,
// so a second like-named DataVariable under it is permitted rather than refused. That permission is the
// second half of the request: an item bearing the same name under HasComponent shall be accepted, which pins
// the check to the relationship rather than to the parent. Both results are asserted together with what each
// left in the address space. The fixture's delegate applies no browseName policy of its own, so a refusal
// observed here can only be the SDK's.
// @relation(AC-SVR-NM-AN-027-BROWSENAMEDUPLICATED, scope=function)
TEST_F(ComplianceAddNodesParameterValidation, ABrowseNameCollidingWithASiblingOnTheSameReferenceTypeIsRefused)
{
  const auto incumbentId = NodeId{mNamespaceIndex, uint32_t{9900}};
  const auto collidingId = NodeId{mNamespaceIndex, uint32_t{9901}};
  const auto otherRelationshipId = NodeId{mNamespaceIndex, uint32_t{9902}};
  const auto sharedName = QualifiedName{mNamespaceIndex, "SharedSiblingName"};

  // The incumbent Property is created over the wire by the same service, so the collision the second
  // request runs into is a real one held by a real Node under a real relationship.
  {
    AddNodesItem incumbent;
    incumbent.parent_node_id() = ExpandedNodeId{mParentFolderId};
    incumbent.reference_type_id() = NodeId{ReferenceTypeId::HasProperty};
    incumbent.requested_new_node_id() = ExpandedNodeId{incumbentId};
    incumbent.browse_name() = sharedName;
    incumbent.node_class() = NodeClass::Variable;
    incumbent.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::PropertyType}};

    AddNodesRequest req;
    req.nodes_to_add().push_back(std::move(incumbent));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good())
      << "the incumbent Property must be created, or there is no collision to observe";
    ASSERT_EQ(resp.results()[0].added_node_id(), incumbentId);
  }

  // (a) Same parent, same HasProperty relationship, same browseName: a second Property of one Node
  //     bearing an existing Property's name, which Part 3 section 5.6.3 does not permit.
  AddNodesItem colliding;
  colliding.parent_node_id() = ExpandedNodeId{mParentFolderId};
  colliding.reference_type_id() = NodeId{ReferenceTypeId::HasProperty};
  colliding.requested_new_node_id() = ExpandedNodeId{collidingId};
  colliding.browse_name() = sharedName;
  colliding.node_class() = NodeClass::Variable;
  colliding.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::PropertyType}};

  // (b) Same parent, same browseName, but a DataVariable under HasComponent: a different
  //     relationship, unconstrained under a plain instance, so the item shall be accepted.
  AddNodesItem otherRelationship;
  otherRelationship.parent_node_id() = ExpandedNodeId{mParentFolderId};
  otherRelationship.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  otherRelationship.requested_new_node_id() = ExpandedNodeId{otherRelationshipId};
  otherRelationship.browse_name() = sharedName;
  otherRelationship.node_class() = NodeClass::Variable;
  otherRelationship.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(colliding));
  req.nodes_to_add().push_back(std::move(otherRelationship));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadBrowseNameDuplicated))
    << "a browseName already held by a Property of the same parent shall return "
       "BadBrowseNameDuplicated; got "
    << to_string(resp.results()[0].status_code());
  EXPECT_THAT(resp.results()[1], Good())
    << "the uniqueness rule is scoped to the relationship: a DataVariable under HasComponent may "
       "share a browseName with a Property of the same plain instance; got "
    << to_string(resp.results()[1].status_code());

  // The refusal of (a) is only meaningful if it created nothing at the id it asked for.
  auto collidingRead = mSession->attributes().try_read_sync(read_value(collidingId, AttributeId::BrowseName));
  ASSERT_THAT(collidingRead, Good());
  auto collidingResp = std::move(collidingRead).value();
  ASSERT_EQ(collidingResp.results().size(), 1u);
  EXPECT_THAT(collidingResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a Node refused for a duplicated browseName shall not exist";

  // The acceptance of (b) is only meaningful if the Node really was created.
  auto otherRead =
    mSession->attributes().try_read_sync(read_value(otherRelationshipId, AttributeId::BrowseName));
  ASSERT_THAT(otherRead, Good());
  auto otherResp = std::move(otherRead).value();
  ASSERT_EQ(otherResp.results().size(), 1u);
  EXPECT_THAT(otherResp.results()[0], Good()) << "a Node accepted under a different relationship shall exist";
  EXPECT_FALSE(otherResp.results()[0].value().empty()) << "that Node shall carry a BrowseName";

  // The address space itself carries the outcome: exactly one child of the parent bears the shared
  // name under HasProperty, and exactly one bears it under HasComponent.
  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no children at all - the counts below would be vacuous";

  std::size_t sameRelationshipMatches = 0;
  std::size_t otherRelationshipMatches = 0;
  for (const auto& ref : parentResp.results()[0].references())
  {
    if (!ref.is_forward())
      continue;
    std::string name = ref.browse_name().name();
    if (name != std::string{"SharedSiblingName"})
      continue;
    if (ref.reference_type_id() == NodeId{ReferenceTypeId::HasProperty})
      ++sameRelationshipMatches;
    else if (ref.reference_type_id() == NodeId{ReferenceTypeId::HasComponent})
      ++otherRelationshipMatches;
  }
  EXPECT_EQ(sameRelationshipMatches, 1u)
    << "only the incumbent shall bear that browseName under HasProperty; a second one means the "
       "refusal did not happen and the parent addresses two Properties by one name";
  EXPECT_EQ(otherRelationshipMatches, 1u)
    << "the Node attached by a different ReferenceType shall be present, since sharing a browseName "
       "across relationships is permitted";
}

// Part 4 section 5.7.2.4: the `nodeAttributes` ExtensionObject an AddNodes item carries is not free-form
// application data - the attribute set a Node may hold is fixed by its NodeClass, so the decoded
// attributes structure must be the one that NodeClass calls for, and Bad_NodeAttributesInvalid is the
// operation-level code when it is not. A plausible implementation never looks inside the ExtensionObject
// at all: it reads nodeClass, builds the Node, and lets the attributes fall on the floor - which is how
// an Object arrives carrying VariableAttributes and is accepted, leaving a Node whose DataType,
// ValueRank and AccessLevel were asked for and can never be read back. The fixture's delegate applies no
// attribute policy of its own, so a refusal observed here can only have come from the SDK.
// @relation(AC-SVR-NM-AN-028-NODEATTRIBUTESINVALID, scope=function)
TEST_F(ComplianceAddNodesParameterValidation, AttributesThatDoNotMatchTheNodeClassAreRefused)
{
  const auto nodeId = NodeId{mNamespaceIndex, uint32_t{9950}};

  AddNodesItem object;
  object.parent_node_id() = ExpandedNodeId{mParentFolderId};
  object.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  object.requested_new_node_id() = ExpandedNodeId{nodeId};
  object.browse_name() = QualifiedName{mNamespaceIndex, "ObjectWithVariableAttributes"};
  object.node_class() = NodeClass::Object;
  object.type_definition() = ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}};

  // VariableAttributes against NodeClass::Object: every field below is one an Object cannot hold.
  auto variableAttributes = std::make_unique<VariableAttributes>();
  // The AttributeWriteMask bits for AccessLevel, DataType, DisplayName, UserAccessLevel and ValueRank,
  // so the attributes are not merely of the wrong type but declare Variable-only fields as specified.
  variableAttributes->specified_attributes() = 1u | 16u | 64u | 16384u | 131072u;
  variableAttributes->display_name() = LocalizedText{"", "ObjectWithVariableAttributes"};
  variableAttributes->data_type() = NodeId{uint16_t{0}, uint32_t{24}};
  variableAttributes->value_rank() = -1;
  variableAttributes->access_level() = 1u;
  variableAttributes->user_access_level() = 1u;
  std::unique_ptr<Structure> attributes = std::move(variableAttributes);
  object.node_attributes() = std::move(attributes);

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(object));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeAttributesInvalid))
    << "an Object supplying VariableAttributes shall return BadNodeAttributesInvalid; got "
    << to_string(resp.results()[0].status_code());

  // The refusal is only meaningful if it created nothing at the id the refused item asked for.
  auto readResult = mSession->attributes().try_read_sync(read_value(nodeId, AttributeId::BrowseName));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a Node refused for attributes wrong for its NodeClass shall not exist";
}

// Part 4 section 5.7.2: `typeDefinition` must name a TypeDefinitionNode of the kind the new Node's NodeClass
// calls for - an ObjectType for an Object, a VariableType for a Variable - and Bad_TypeDefinitionInvalid
// is the code when it does not. Both stimuli name Nodes that exist, which is the whole point of the
// distinction the criterion draws: the caller must be told their id resolved and their choice was wrong
// (Bad_TypeDefinitionInvalid), not that the id was unknown. A plausible implementation checks only that
// the id resolves to some Node and then hangs a HasTypeDefinition off it, so an instance ends up typed by
// another instance, or an Object ends up typed by a VariableType. The fixture's delegate resolves no type
// definition at all, so a refusal observed here can only have come from the SDK.
// @relation(AC-SVR-NM-AN-029-TYPEDEFINITION-INVALID, scope=function)
TEST_F(ComplianceAddNodesParameterValidation, ATypeDefinitionThatIsNotAnAppropriateTypeNodeIsRefused)
{
  const auto notATypeId = NodeId{mNamespaceIndex, uint32_t{9940}};
  const auto wrongKindId = NodeId{mNamespaceIndex, uint32_t{9941}};

  // (a) The typeDefinition names the test folder - an Object instance, which exists but is not a type.
  AddNodesItem notAType;
  notAType.parent_node_id() = ExpandedNodeId{mParentFolderId};
  notAType.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  notAType.requested_new_node_id() = ExpandedNodeId{notATypeId};
  notAType.browse_name() = QualifiedName{mNamespaceIndex, "TypedByAnInstance"};
  notAType.node_class() = NodeClass::Object;
  notAType.type_definition() = ExpandedNodeId{mParentFolderId};

  // (b) The typeDefinition names a real TypeDefinitionNode, but of the wrong kind for the NodeClass:
  //     BaseDataVariableType is a VariableType and cannot type an Object.
  AddNodesItem wrongKind;
  wrongKind.parent_node_id() = ExpandedNodeId{mParentFolderId};
  wrongKind.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  wrongKind.requested_new_node_id() = ExpandedNodeId{wrongKindId};
  wrongKind.browse_name() = QualifiedName{mNamespaceIndex, "ObjectTypedByAVariableType"};
  wrongKind.node_class() = NodeClass::Object;
  wrongKind.type_definition() = ExpandedNodeId{NodeId{VariableTypeId::BaseDataVariableType}};

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(notAType));
  req.nodes_to_add().push_back(std::move(wrongKind));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTypeDefinitionInvalid))
    << "a typeDefinition naming a Node that exists but is not a type shall return "
       "BadTypeDefinitionInvalid, not BadNodeIdUnknown; got "
    << to_string(resp.results()[0].status_code());
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadTypeDefinitionInvalid))
    << "a typeDefinition whose kind does not match the item's NodeClass shall return "
       "BadTypeDefinitionInvalid, not BadNodeIdUnknown; got "
    << to_string(resp.results()[1].status_code());

  // Neither refusal shall leave a Node behind at the id it asked for.
  auto notATypeRead = mSession->attributes().try_read_sync(read_value(notATypeId, AttributeId::BrowseName));
  ASSERT_THAT(notATypeRead, Good());
  auto notATypeResp = std::move(notATypeRead).value();
  ASSERT_EQ(notATypeResp.results().size(), 1u);
  EXPECT_THAT(notATypeResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "the Node refused for a typeDefinition that is not a type shall not exist";

  auto wrongKindRead = mSession->attributes().try_read_sync(read_value(wrongKindId, AttributeId::BrowseName));
  ASSERT_THAT(wrongKindRead, Good());
  auto wrongKindResp = std::move(wrongKindRead).value();
  ASSERT_EQ(wrongKindResp.results().size(), 1u);
  EXPECT_THAT(wrongKindResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "the Node refused for a typeDefinition of the wrong kind shall not exist";
}

// Part 4 section 5.7.2: "each Node is added as the TargetNode of a HierarchicalReference to ensure that the
// AddressSpace is fully connected". Two ways to break that are driven here - attaching by a
// ReferenceType that is not hierarchical (HasTypeDefinition), and supplying no parent at all - and the
// criterion's observation is a conjunction: both are refused, and every Node that IS added joins the
// hierarchy. A plausible implementation validates that the referenceTypeId resolves and stops there,
// which leaves a Node hanging off a non-hierarchical reference: reachable only by whoever holds its
// NodeId, invisible to a hierarchical browse, and never reached by a recursive delete. The third item is
// the control - a well-formed hierarchical attach - so a pass cannot come from AddNodes being broken
// outright. The no-parent item is resolved by the SDK itself before authorization, so its refusal is the
// server's; the non-hierarchical item is the one this fixture's delegate would happily create.
// @relation(AC-SVR-NM-AN-031-HIERARCHICAL-ATTACHMENT, scope=function)
TEST_F(ComplianceAddNodesParameterValidation, EveryAddedNodeAttachesHierarchicallyFromAnExistingParent)
{
  const auto nonHierarchicalId = NodeId{mNamespaceIndex, uint32_t{9930}};
  const auto noParentId = NodeId{mNamespaceIndex, uint32_t{9931}};
  const auto attachedId = NodeId{mNamespaceIndex, uint32_t{9932}};

  // (a) HasTypeDefinition is a subtype of NonHierarchicalReferences, so it cannot connect the new Node
  //     into the hierarchy however well it resolves.
  AddNodesItem nonHierarchical;
  nonHierarchical.parent_node_id() = ExpandedNodeId{mParentFolderId};
  nonHierarchical.reference_type_id() = NodeId{ReferenceTypeId::HasTypeDefinition};
  nonHierarchical.requested_new_node_id() = ExpandedNodeId{nonHierarchicalId};
  nonHierarchical.browse_name() = QualifiedName{mNamespaceIndex, "NonHierarchicalAttach"};
  nonHierarchical.node_class() = NodeClass::Object;
  nonHierarchical.type_definition() = ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}};

  // (b) No parent at all: there is no Node for the new Node to be the TargetNode of.
  AddNodesItem noParent;
  noParent.parent_node_id() = ExpandedNodeId{NodeId{}};
  noParent.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  noParent.requested_new_node_id() = ExpandedNodeId{noParentId};
  noParent.browse_name() = QualifiedName{mNamespaceIndex, "UnparentedNode"};
  noParent.node_class() = NodeClass::Object;
  noParent.type_definition() = ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}};

  // (c) The control: a hierarchical attach from a parent that exists, which shall be accepted.
  AddNodesItem attached;
  attached.parent_node_id() = ExpandedNodeId{mParentFolderId};
  attached.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  attached.requested_new_node_id() = ExpandedNodeId{attachedId};
  attached.browse_name() = QualifiedName{mNamespaceIndex, "HierarchicalAttach"};
  attached.node_class() = NodeClass::Object;
  attached.type_definition() = ExpandedNodeId{NodeId{ObjectTypeId::BaseObjectType}};

  AddNodesRequest req;
  req.nodes_to_add().push_back(std::move(nonHierarchical));
  req.nodes_to_add().push_back(std::move(noParent));
  req.nodes_to_add().push_back(std::move(attached));

  auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 3u);

  EXPECT_TRUE(resp.results()[0].status_code().is_bad())
    << "a Node attached by a non-hierarchical ReferenceType would not join the hierarchy and shall be "
       "refused; got "
    << to_string(resp.results()[0].status_code());
  EXPECT_TRUE(resp.results()[1].status_code().is_bad())
    << "a Node with no parent has nothing to be the TargetNode of and shall be refused; got "
    << to_string(resp.results()[1].status_code());
  EXPECT_TRUE(resp.results()[2].status_code().is_good())
    << "a hierarchical attach from an existing parent shall be accepted, or the refusals above prove "
       "nothing; got "
    << to_string(resp.results()[2].status_code());

  // Neither refused item shall have left a Node behind.
  auto nonHierarchicalRead =
    mSession->attributes().try_read_sync(read_value(nonHierarchicalId, AttributeId::BrowseName));
  ASSERT_THAT(nonHierarchicalRead, Good());
  auto nonHierarchicalResp = std::move(nonHierarchicalRead).value();
  ASSERT_EQ(nonHierarchicalResp.results().size(), 1u);
  EXPECT_THAT(nonHierarchicalResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a Node refused for a non-hierarchical attach shall not exist";

  auto noParentRead = mSession->attributes().try_read_sync(read_value(noParentId, AttributeId::BrowseName));
  ASSERT_THAT(noParentRead, Good());
  auto noParentResp = std::move(noParentRead).value();
  ASSERT_EQ(noParentResp.results().size(), 1u);
  EXPECT_THAT(noParentResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a Node refused for having no parent shall not exist";

  // The second half of the observation: every Node that was added joins the hierarchy. The control is
  // reachable from the parent by a hierarchical browse; the refused Node is reachable by nothing.
  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no children at all - the checks below would be vacuous";

  bool controlFound = false;
  for (const auto& ref : parentResp.results()[0].references())
  {
    if (!ref.is_forward())
      continue;
    EXPECT_NE(ref.node_id().node_id(), nonHierarchicalId)
      << "a refused non-hierarchical attach shall leave no reference from the parent";
    if (ref.node_id().node_id() == attachedId)
    {
      controlFound = true;
      EXPECT_EQ(ref.reference_type_id(), NodeId{ReferenceTypeId::Organizes})
        << "the accepted Node shall be attached by the hierarchical ReferenceType that was asked for";
    }
  }
  EXPECT_TRUE(controlFound) << "the Node that was added shall be reachable from its parent by browse";
}

// ===========================================================================
// AddReferences - obligations the SDK owes on the reference parameters themselves.
//
// `BasicNodeManagementDelegate` at the top of this file performs its own targetNodeClass check (lines
// 351-363), so `NM_AR_024_BadNodeClassInvalid` observes that `if` and would stay green against a server
// that validates nothing. The delegate below applies no class policy at all: it resolves the source and
// creates the reference it was handed. `NodeManagementService` only dispatches items that survived its
// own per-item validation and copies the delegate's status straight through, so a refusal observed on
// this fixture can only have come from the SDK.
// ===========================================================================

class PermissiveReferenceDelegate final : public NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      AddNodesResult result;
      result.status_code() = Status::BadServiceUnsupported;
      batch.items.emplace_back(std::move(result));
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<AddReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.reserve(items.size());

    for (auto& item : items)
    {
      try
      {
        auto sourceResult = addressSpace.try_find_node_sync(item.source_node_id());
        if (sourceResult.is_bad())
        {
          batch.items.emplace_back(VoidResult{StatusCode{Status::BadSourceNodeIdInvalid}});
          continue;
        }

        // No targetNodeClass check and no reference-type policy: the reference asked for is created.
        auto source = sourceResult.value();
        auto addResult = source.try_add_reference_sync(
          item.reference_type_id(), item.target_node_id().node_id(), item.is_forward());
        batch.items.emplace_back(addResult.is_good() ? VoidResult{} : VoidResult{addResult.status_code()});
      }
      catch (const UaException& ex)
      {
        batch.items.emplace_back(VoidResult{StatusCode{ex.status()}});
      }
      catch (...)
      {
        batch.items.emplace_back(VoidResult{StatusCode{Status::BadInternalError}});
      }
    }

    callback(std::move(batch));
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteNodesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    callback(reference_delegate_unsupported(items.size()));
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    callback(reference_delegate_unsupported(items.size()));
  }

private:
  /// The tests on this fixture only exercise AddReferences; the other operations are not implemented.
  static BatchResult<VoidResult> reference_delegate_unsupported(std::size_t count)
  {
    BatchResult<VoidResult> batch;
    batch.items.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
      batch.items.emplace_back(VoidResult{StatusCode{Status::BadServiceUnsupported}});
    }
    return batch;
  }
};

class ComplianceAddReferencesParameterValidation : public ComplianceNodeManagement
{
protected:
  void SetUp() override
  {
    ComplianceNodeManagement::SetUp();
    ASSERT_TRUE(mServer.has_value());
    mReferenceHandler = std::make_shared<PermissiveReferenceDelegate>();
    mServer->set_node_management_delegate(ua::test::offloaded(mReferenceHandler));
  }

  /// Seeds a Node directly into the address space, attached to nothing, so the only way it can come to
  /// hang beneath the test folder is the AddReferences under test. AddNodes reports BadServiceUnsupported
  /// on this fixture's delegate, so reference targets cannot be created over the wire.
  void seed_node(const NodeId& nodeId, NodeClass nodeClass, const char* browseName)
  {
    auto addressSpace = mServer->address_space();
    auto creation = addressSpace.try_create_node_sync(nodeId, nodeClass, {});
    ASSERT_TRUE(creation.is_good()) << "the fixture could not seed " << browseName << ": "
                                    << to_string(creation.status_code());
    auto node = creation.value();
    node.set_browse_name(QualifiedName{mNamespaceIndex, browseName});
    node.set_display_name(LocalizedText{"", browseName});
  }

  std::shared_ptr<PermissiveReferenceDelegate> mReferenceHandler;
};

// The parameter is mandatory rather than advisory because the TargetNode may live on a Server this one
// cannot introspect: for a remote target there is nothing to check the class against, so a Server that
// inferred it locally and ignored it remotely would accept a Reference it cannot describe. Both ways of
// getting it wrong are driven - the class omitted, and a class that contradicts a target this Server can
// resolve - and a third item supplies the class the target really has, so a pass cannot come from
// AddReferences failing wholesale. What each item left in the address space is checked as well, because
// a Reference created despite a refusal is the outcome the parameter exists to prevent.
// Part 4 section 5.7.3.2 - the Client shall specify the targetNodeClass since the TargetNode might not be
// accessible directly by the Server.
// @verifies AC-SVR-NM-AR-004-TARGETNODECLASS-REQUIRED
TEST_F(ComplianceAddReferencesParameterValidation, TheTargetNodeClassMustBeStatedAndMustAgreeWithTheTarget)
{
  const auto unstatedTargetId = NodeId{mNamespaceIndex, uint32_t{9100}};
  const auto contradictedTargetId = NodeId{mNamespaceIndex, uint32_t{9101}};
  const auto controlTargetId = NodeId{mNamespaceIndex, uint32_t{9102}};

  ASSERT_NO_FATAL_FAILURE(seed_node(unstatedTargetId, NodeClass::Object, "UnstatedClassTarget"));
  ASSERT_NO_FATAL_FAILURE(seed_node(contradictedTargetId, NodeClass::Object, "ContradictedClassTarget"));
  ASSERT_NO_FATAL_FAILURE(seed_node(controlTargetId, NodeClass::Object, "StatedClassTarget"));

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      // (a) The client states no class at all.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, unstatedTargetId)
      .target_node_class(NodeClass::Unspecified)
      // (b) The client states a class the local target contradicts.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, contradictedTargetId)
      .target_node_class(NodeClass::Variable)
      // (c) The control: the class the target really has.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, controlTargetId)
      .target_node_class(NodeClass::Object));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 3u);

  EXPECT_TRUE(resp.results()[0].is_bad())
    << "an AddReferences item that states no targetNodeClass shall be refused: the Server may be unable "
       "to supply one itself, so the parameter is required rather than inferred; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_bad())
    << "a targetNodeClass that contradicts a target this Server can resolve shall be refused; got "
    << to_string(resp.results()[1]);
  EXPECT_TRUE(resp.results()[2].is_good())
    << "the same Reference stating the class the target really has shall be accepted, or the refusals "
       "above prove nothing; got "
    << to_string(resp.results()[2]);

  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no references at all - the checks below would be vacuous";

  bool controlFound = false;
  for (const auto& ref : parentResp.results()[0].references())
  {
    if (!ref.is_forward())
      continue;
    EXPECT_NE(ref.node_id().node_id(), unstatedTargetId)
      << "a Reference refused for stating no targetNodeClass shall not have been created";
    EXPECT_NE(ref.node_id().node_id(), contradictedTargetId)
      << "a Reference refused for a contradicted targetNodeClass shall not have been created";
    if (ref.node_id().node_id() == controlTargetId)
      controlFound = true;
  }
  EXPECT_TRUE(controlFound) << "the correctly declared Reference shall be visible in Browse";
}

// A `targetServerUri` names the Server the TargetNode lives on, and it is all this Server has to go on:
// it cannot resolve the target, so if the URI is unusable there is nothing left to validate and nothing
// the Reference could mean. Bad_ServerUriInvalid says exactly that. A plausible implementation stores
// the string as opaque metadata, which leaves a Reference whose ExpandedNodeId names a Server no client
// can resolve - a dangling target that Browse will hand out forever. The control item differs only in
// carrying no URI at all, so the refusal can be attributed to the URI and nothing else.
// Part 4 section 5.7.3.3 - Bad_ServerUriInvalid: invalid server URI.
// @verifies AC-SVR-NM-AR-022-SERVERURIINVALID
TEST_F(ComplianceAddReferencesParameterValidation, AReferenceNamingAnUnusableTargetServerUriIsRefused)
{
  const auto remoteTargetId = NodeId{mNamespaceIndex, uint32_t{9110}};
  const auto localTargetId = NodeId{mNamespaceIndex, uint32_t{9111}};

  ASSERT_NO_FATAL_FAILURE(seed_node(remoteTargetId, NodeClass::Object, "RemoteUriTarget"));
  ASSERT_NO_FATAL_FAILURE(seed_node(localTargetId, NodeClass::Object, "LocalUriTarget"));

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      // Not a URI at all: no scheme, spaces, stray delimiters. Nothing this Server could register.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, remoteTargetId)
      .target_node_class(NodeClass::Object)
      .target_server_uri(":// not a server uri ://")
      // The control differs only in naming no other Server.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, localTargetId)
      .target_node_class(NodeClass::Object));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadServerUriInvalid))
    << "a targetServerUri this Server can neither recognise nor register shall return "
       "BadServerUriInvalid; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "the same Reference naming no other Server shall be accepted, or the refusal above proves "
       "nothing; got "
    << to_string(resp.results()[1]);

  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no references at all - the check below would be vacuous";

  for (const auto& ref : parentResp.results()[0].references())
  {
    EXPECT_NE(ref.node_id().node_id(), remoteTargetId)
      << "a Reference refused for an invalid targetServerUri shall not have been created";
  }
}

// Part 4 section 5.7.3.1: "In certain cases, adding new References to the AddressSpace shall require that the
// Server add new Server ids to the Server's ServerArray Variable. For this reason, remote Servers are
// identified by their URI and not by their ServerArray index." A `serverIndex` is an index into that array
// and means nothing without an entry to index: a Reference carrying one the array does not cover names a
// Server the client cannot resolve, and Browse hands that unresolvable target out to every client
// thereafter. The obligation is conditional on the Server taking the Reference on - Table 27 lets it refuse
// the item instead (Bad_ServerUriInvalid, Bad_ReferenceLocalOnly) - so the test drives the stimulus and then
// follows whichever way the Server went: refuse, and nothing may have been created and nothing may have been
// registered; accept, and the URI shall be in the ServerArray with the Reference's serverIndex resolving
// through it. The outcome permitted by neither branch is the third one, acceptance with the array left
// alone, and that is what the acceptance branch below asserts against. A control Reference naming no other
// Server runs in the same request, so the refusal branch cannot be AddReferences failing wholesale.
// @verifies AC-SVR-NM-AR-001-CROSS-SERVER-REFERENCE-REGISTERS-URI
// The execution-evidence reader requires the full TEST_F identity on one line.
// clang-format off
TEST_F(ComplianceAddReferencesParameterValidation, AReferenceToANodeOnAnotherServerRegistersThatServerInTheServerArray)
// clang-format on
{
  const std::string remoteServerUri = "urn:test:remote:peer:server";
  const auto remoteTargetId = NodeId{mNamespaceIndex, uint32_t{9160}};
  const auto localControlId = NodeId{mNamespaceIndex, uint32_t{9161}};

  ASSERT_NO_FATAL_FAILURE(seed_node(localControlId, NodeClass::Object, "LocalControlTarget"));

  // Reads Server.ServerArray over the wire. Returns empty on any read failure, which the caller asserts on.
  auto readServerArray = [this]() -> std::vector<std::string>
  {
    std::vector<std::string> uris;
    auto result = mSession->attributes().try_read_sync(read_value(NodeId{VariableId::Server_ServerArray}));
    EXPECT_THAT(result, Good()) << "Server.ServerArray must be readable";
    if (result.is_bad())
      return uris;
    auto resp = std::move(result).value();
    EXPECT_EQ(resp.results().size(), 1u);
    if (resp.results().size() != 1u)
      return uris;
    EXPECT_THAT(resp.results()[0], Good()) << "Server.ServerArray must read Good";
    if (resp.results()[0].value().empty())
      return uris;
    const auto entries = resp.results()[0].value().as<Array<String>>();
    uris.reserve(entries.size());
    for (std::size_t i = 0; i < entries.size(); ++i)
      uris.push_back(std::string{static_cast<std::string_view>(entries[i])});
    return uris;
  };

  // The population the observation quantifies over starts out empty: the Server does not already name the
  // remote Server, so an entry found afterwards can only have been added by the stimulus.
  const auto before = readServerArray();
  ASSERT_FALSE(before.empty())
    << "the ServerArray is empty or unreadable, so nothing below could be observed";
  GTEST_LOG_(INFO) << "ServerArray before the stimulus: " << before.size() << " entries, [0]=" << before[0];
  for (const auto& uri : before)
  {
    ASSERT_NE(uri, remoteServerUri) << "the ServerArray already names " << remoteServerUri
                                    << ", so the observation would be satisfied before the stimulus ran";
  }

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      // The stimulus: a target on a Server this one has never heard of, identified by URI as section 5.7.3.1
      // requires. The URI is well formed and registrable - the unusable-URI case is AR-022's.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, remoteTargetId)
      .target_node_class(NodeClass::Object)
      .target_server_uri(remoteServerUri)
      // The control differs only in naming no other Server.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, localControlId)
      .target_node_class(NodeClass::Object));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);
  ASSERT_TRUE(resp.results()[1].is_good())
    << "the control Reference, naming no other Server, must be accepted, or neither branch below is "
       "attributable to the targetServerUri; got "
    << to_string(resp.results()[1]);

  const auto after = readServerArray();
  ASSERT_FALSE(after.empty()) << "the ServerArray must still be readable after the stimulus";
  GTEST_LOG_(INFO) << "ServerArray after the stimulus: " << after.size() << " entries";

  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no references at all - the control Reference was accepted, so this is a Browse "
       "failure and the checks below would be vacuous";

  if (resp.results()[0].is_bad())
  {
    // Refusal is permitted (Table 27), but it must leave the address space and the ServerArray untouched.
    EXPECT_EQ(after.size(), before.size())
      << "an AddReferences item the Server refused shall not have registered its targetServerUri";
    for (const auto& uri : after)
    {
      EXPECT_NE(uri, remoteServerUri)
        << "a refused item shall not leave the remote Server in the ServerArray";
    }
    for (const auto& ref : parentResp.results()[0].references())
    {
      EXPECT_NE(ref.node_id().node_id(), remoteTargetId)
        << "a refused cross-server item shall not have created a Reference";
    }
    // A pass, not an abstention. This branch is a conforming outcome that the three assertions above
    // have just verified - refusal is permitted by Table 27, and the obligation on a refusal is that
    // nothing was created and nothing registered. A skip here would say "I checked nothing",
    // which is both false and enough to make this test's coverage marker read as dead.
    SUCCEED() << "this Server declines cross-server References (" << to_string(resp.results()[0])
              << "), which Part 4 Table 27 permits, so the registration limb has no subject and the "
                 "refusal was verified to have left the address space and the ServerArray untouched";
    return;
  }

  // The Server took the Reference on, so it undertook to address a Node on another Server and
  // section 5.7.3.1's registration falls due.
  std::size_t registeredIndex = after.size();
  for (std::size_t i = 0; i < after.size(); ++i)
  {
    if (after[i] == remoteServerUri)
      registeredIndex = i;
  }
  ASSERT_LT(registeredIndex, after.size())
    << "the Server accepted a Reference whose target lives on " << remoteServerUri
    << " and left that Server out of its ServerArray: the Reference's serverIndex then indexes nothing and "
       "no client can resolve the target. Either register the URI or refuse the item with "
       "Bad_ServerUriInvalid";

  bool referenceFound = false;
  uint32_t referenceServerIndex = 0;
  for (const auto& ref : parentResp.results()[0].references())
  {
    if (ref.node_id().node_id() != remoteTargetId)
      continue;
    referenceFound = true;
    referenceServerIndex = ref.node_id().server_index();
  }
  ASSERT_TRUE(referenceFound)
    << "an AddReferences item reported Good, so the Reference it asked for shall be visible in Browse";
  ASSERT_LT(static_cast<std::size_t>(referenceServerIndex), after.size())
    << "the Reference's serverIndex (" << referenceServerIndex
    << ") is outside the ServerArray, so it resolves to no Server at all";
  EXPECT_EQ(after[referenceServerIndex], remoteServerUri)
    << "the Reference's serverIndex shall resolve through the ServerArray to the Server its target lives "
       "on; index "
    << referenceServerIndex << " names " << after[referenceServerIndex] << " instead";
}

// A `targetNodeId` that is structurally unusable is the case this obligation covers: the Reference would
// resolve to nothing whatever the address space held, and Browse would hand the client a target it can
// never read. A well-formed id that simply names no Node is deliberately not driven here, because Part 3
// section 4.3.4 says "OPC UA does not require that the TargetNode exists, thus References may point to a Node
// that does not exist" - a Server may refuse such an item, but nothing obliges it to, and Part 4
// section 5.7.4.1 leaves References to deleted Nodes unresolved, so dangling References are a state the model
// sanctions. The control names a Node that does exist, so the refusal cannot be AddReferences failing
// outright. Part 3 section 4.3.4 - References may point to a Node that does not exist; only an unusable id is
// invalid. Part 4 section 5.7.3.3 - Bad_TargetNodeIdInvalid: invalid target node id.
// @verifies AC-SVR-NM-AR-023-TARGETNODEIDINVALID
TEST_F(ComplianceAddReferencesParameterValidation, AReferenceToALocalTargetThatDoesNotExistIsRefused)
{
  const auto realTargetId = NodeId{mNamespaceIndex, uint32_t{9120}};

  ASSERT_NO_FATAL_FAILURE(seed_node(realTargetId, NodeClass::Object, "RealTarget"));

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, NodeId{})
      .target_node_class(NodeClass::Object)
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, realTargetId)
      .target_node_class(NodeClass::Object));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTargetNodeIdInvalid))
    << "a null targetNodeId is unusable however the address space is populated, so it shall return "
       "BadTargetNodeIdInvalid rather than create a Reference to nothing; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "the same Reference to a usable target shall be accepted, or the refusal above proves nothing; got "
    << to_string(resp.results()[1]);

  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no references at all - the check below would be vacuous";

  for (const auto& ref : parentResp.results()[0].references())
  {
    EXPECT_FALSE(ref.node_id().node_id().is_null())
      << "a refused AddReferences shall leave no Reference pointing at a null target";
  }
}

// Where the target IS resolvable the declared class is checkable, and Bad_NodeClassInvalid is the code
// that says the id was right and the class was wrong. The distinction matters to the caller: a
// Bad_TargetNodeIdInvalid would send them looking for a Node that is in fact there. It matters to every
// other client too, because Browse reports `nodeClass` out of the Reference rather than out of the
// target - a Reference that misdeclares its target makes every NodeClass-filtered Browse return a Node
// the client will discard unread. The control declares the class the target really has.
// Part 4 section 5.7.3.3 - Bad_NodeClassInvalid: invalid node class.
// @verifies AC-SVR-NM-AR-024-NODECLASSINVALID
TEST_F(ComplianceAddReferencesParameterValidation, AMisdeclaredTargetNodeClassIsReportedAsAnInvalidNodeClass)
{
  const auto misdeclaredId = NodeId{mNamespaceIndex, uint32_t{9130}};
  const auto controlId = NodeId{mNamespaceIndex, uint32_t{9131}};

  // Both targets are Variables, so the class the first item declares (Object) is wrong about a Node the
  // Server can resolve - not about a Node it cannot find.
  ASSERT_NO_FATAL_FAILURE(seed_node(misdeclaredId, NodeClass::Variable, "MisdeclaredVariable"));
  ASSERT_NO_FATAL_FAILURE(seed_node(controlId, NodeClass::Variable, "CorrectlyDeclaredVariable"));

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, misdeclaredId)
      .target_node_class(NodeClass::Object)
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, controlId)
      .target_node_class(NodeClass::Variable));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeClassInvalid))
    << "a targetNodeClass that disagrees with a resolvable target shall return BadNodeClassInvalid; got "
    << to_string(resp.results()[0]);
  EXPECT_NE(to_string(resp.results()[0]), to_string(StatusCode{Status::BadTargetNodeIdInvalid}))
    << "the target resolved, so the caller shall be told their class was wrong rather than sent looking "
       "for a Node that is in fact present";
  EXPECT_TRUE(resp.results()[1].is_good())
    << "the same Reference declaring the class the target really has shall be accepted, or the refusal "
       "above proves nothing; got "
    << to_string(resp.results()[1]);

  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no references at all - the check below would be vacuous";

  for (const auto& ref : parentResp.results()[0].references())
  {
    EXPECT_NE(ref.node_id().node_id(), misdeclaredId)
      << "a refused AddReferences shall create no Reference, and least of all one whose Browse result "
         "reports a NodeClass its target does not have";
  }
}

// HasTypeDefinition is not the ReferenceType this obligation is about: Part 3 section 4.5.2 states in as many
// words that "instances may point with their HasTypeDefinition Reference to a TypeDefinitionNode in a
// different Server", and section 4.5.1 adds that the TypeDefinitionNodes a generic Client needs "may exist in
// another Server". What the same clause does bind to one Server is the composition of a type - "A
// TypeDefinitionNode and its InstanceDeclarations shall always reside in the same Server" - so the
// Reference no Server may store is a HasComponent from a TypeDefinitionNode to an InstanceDeclaration
// hosted elsewhere, and Bad_ReferenceLocalOnly is the code that reports the attempt. A plausible
// implementation validates the target's serverIndex only for the ReferenceTypes it happens to think
// about, or not at all, and stores the cross-Server Reference anyway. The control item differs only in
// that its InstanceDeclaration lives here, so the refusal can be attributed to the remote target alone.
// Part 3 section 4.5.2 - a TypeDefinitionNode and its InstanceDeclarations shall always reside in the same
// Server, while a HasTypeDefinition Reference may cross Servers.
// Part 4 section 5.7.3.3 - Bad_ReferenceLocalOnly: reference type not valid for remote Server reference.
// @verifies AC-SVR-NM-AR-026-REFERENCELOCALONLY
TEST_F(ComplianceAddReferencesParameterValidation, ALocalOnlyReferenceTypeToARemoteTargetIsRefused)
{
  const auto sourceTypeId = NodeId{mNamespaceIndex, uint32_t{9141}};
  const auto remoteMemberId = NodeId{mNamespaceIndex, uint32_t{99002}};
  const auto localMemberId = NodeId{mNamespaceIndex, uint32_t{9140}};

  ASSERT_NO_FATAL_FAILURE(seed_node(sourceTypeId, NodeClass::ObjectType, "LocalTypeDefinition"));
  ASSERT_NO_FATAL_FAILURE(seed_node(localMemberId, NodeClass::Variable, "LocalInstanceDeclaration"));

  AddReferencesRequest req;
  {
    // The target names another Server, which an InstanceDeclaration of a type defined here can never do.
    ExpandedNodeId remoteTarget{remoteMemberId};
    remoteTarget.server_index() = 1;

    AddReferencesItem remote;
    remote.source_node_id() = sourceTypeId;
    remote.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    remote.is_forward() = true;
    remote.target_node_id() = std::move(remoteTarget);
    remote.target_node_class() = NodeClass::Variable;
    req.references_to_add().push_back(std::move(remote));

    // The control differs only in that its target is on this Server.
    AddReferencesItem local;
    local.source_node_id() = sourceTypeId;
    local.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
    local.is_forward() = true;
    local.target_node_id() = ExpandedNodeId{localMemberId};
    local.target_node_class() = NodeClass::Variable;
    req.references_to_add().push_back(std::move(local));
  }

  auto result = mSession->node_management().try_add_references_sync(std::move(req));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadReferenceLocalOnly))
    << "a ReferenceType that is only valid between local Nodes shall return BadReferenceLocalOnly when "
       "its target lives on another Server; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "the same ReferenceType to a target on this Server shall be accepted, or the refusal above proves "
       "nothing; got "
    << to_string(resp.results()[1]);

  auto typeBrowse = mSession->view().try_browse_sync(browse(sourceTypeId));
  ASSERT_THAT(typeBrowse, Good());
  auto typeResp = std::move(typeBrowse).value();
  ASSERT_EQ(typeResp.results().size(), 1u);
  ASSERT_THAT(typeResp.results()[0], Good());
  ASSERT_FALSE(typeResp.results()[0].references().empty())
    << "the type exposes no references at all - the check below would be vacuous";

  for (const auto& ref : typeResp.results()[0].references())
  {
    EXPECT_NE(ref.node_id().node_id(), remoteMemberId)
      << "a Reference refused as local-only shall not have been created";
  }
}

// Accepting a Reference that already exists is not harmless: Browse would then return the same target
// twice from the same source, which a client de-duplicating by NodeId silently hides and a client
// counting references does not. So the obligation has two halves - the refusal, and the address space
// still holding exactly one Reference afterwards - and the second is the one an implementation that
// re-adds blindly, or one that removes and re-inserts, gets wrong. The first add is asserted Good so the
// duplicate the second one runs into is a real Reference and not an artefact of the first also failing.
// Part 4 section 5.7.3.3 - Bad_DuplicateReferenceNotAllowed: reference type between the nodes already
// defined.
// @verifies AC-SVR-NM-AR-028-DUPLICATEREFERENCE
TEST_F(ComplianceAddReferencesParameterValidation, ADuplicateReferenceIsRefusedAndOnlyOneReferenceRemains)
{
  const auto targetId = NodeId{mNamespaceIndex, uint32_t{9150}};
  ASSERT_NO_FATAL_FAILURE(seed_node(targetId, NodeClass::Object, "DuplicateRefTarget"));

  {
    auto result = mSession->node_management().try_add_references_sync(
      AddReferencesBuilder()
        .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, targetId)
        .target_node_class(NodeClass::Object));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_TRUE(resp.results()[0].is_good())
      << "the first Reference must be created, or there is no duplicate to observe; got "
      << to_string(resp.results()[0]);
  }

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, targetId)
      .target_node_class(NodeClass::Object));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadDuplicateReferenceNotAllowed))
    << "a Reference of the same type, direction and endpoints as one that already exists shall return "
       "BadDuplicateReferenceNotAllowed; got "
    << to_string(resp.results()[0]);

  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no references at all - the count below would be vacuous";

  std::size_t matches = 0;
  for (const auto& ref : parentResp.results()[0].references())
  {
    if (!ref.is_forward())
      continue;
    if (ref.reference_type_id() == NodeId{ReferenceTypeId::Organizes} && ref.node_id().node_id() == targetId)
      ++matches;
  }
  EXPECT_EQ(matches, 1u)
    << "Browse reports the same target " << matches
    << " times from one source under one ReferenceType; a client that counts references sees a Reference "
       "that was refused, and one that de-duplicates by NodeId sees nothing wrong at all";
}

// A reflexive hierarchical Reference makes the address space cyclic, so a client walking it never
// terminates - which is why the rule is stated per ReferenceType rather than as a blanket prohibition on
// self-references, and why the code is its own rather than folded into Bad_ReferenceNotAllowed. A
// plausible implementation compares source and target only when the ids are spelled identically, or not
// at all, and leaves a loop in the hierarchy. The control adds the same ReferenceType from the same
// source to a different Node, so the refusal is about the reflexivity and nothing else.
// Part 4 section 5.7.3.3 - Bad_InvalidSelfReference: Server does not allow this type of self reference on
// this node.
// @verifies AC-SVR-NM-AR-029-INVALIDSELFREFERENCE
TEST_F(ComplianceAddReferencesParameterValidation, AReferenceFromANodeToItselfIsRefused)
{
  const auto otherTargetId = NodeId{mNamespaceIndex, uint32_t{9160}};
  ASSERT_NO_FATAL_FAILURE(seed_node(otherTargetId, NodeClass::Object, "SelfReferenceControlTarget"));

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      // Organizes is hierarchical, so this edge would make the folder its own ancestor.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, mParentFolderId)
      .target_node_class(NodeClass::Object)
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, otherTargetId)
      .target_node_class(NodeClass::Object));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadInvalidSelfReference))
    << "a hierarchical Reference whose source and target are the same Node shall return "
       "BadInvalidSelfReference; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "the same ReferenceType from the same source to a different Node shall be accepted, or the "
       "refusal above proves nothing; got "
    << to_string(resp.results()[1]);

  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no references at all - the check below would be vacuous";

  for (const auto& ref : parentResp.results()[0].references())
  {
    EXPECT_NE(ref.node_id().node_id(), mParentFolderId)
      << "a refused self-reference shall leave no edge from the Node to itself; a client walking the "
         "hierarchy from here would not terminate";
  }
}

// Unlike the target, which may be remote, the source must exist here: a Reference is stored on its
// source, so a missing source has nowhere to hold it. The failure mode worth naming is not the refusal
// but what a Server might do instead - invent a placeholder Node to hang the Reference from, which
// creates a Node the client never asked for and nothing will ever delete. The second conjunct therefore
// reads the source id back afterwards, and the control item uses a source that does exist so the
// refusal cannot be AddReferences failing outright.
// Part 4 section 5.7.3.2 - the source Node shall always exist in the Server to add the Reference.
// @verifies AC-SVR-NM-AR-003-SOURCE-MUST-EXIST
// The execution-evidence reader requires the full TEST_F identity on one line.
// clang-format off
TEST_F(ComplianceAddReferencesParameterValidation, AReferenceWhoseSourceDoesNotExistIsRefusedAndCreatesNothing)
// clang-format on
{
  const auto phantomSourceId = NodeId{mNamespaceIndex, uint32_t{99003}};
  const auto targetId = NodeId{mNamespaceIndex, uint32_t{9170}};

  ASSERT_NO_FATAL_FAILURE(seed_node(targetId, NodeClass::Object, "SourcelessRefTarget"));

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(phantomSourceId, NodeId{ReferenceTypeId::Organizes}, targetId)
      .target_node_class(NodeClass::Object)
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, targetId)
      .target_node_class(NodeClass::Object));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_TRUE(resp.results()[0].is_bad())
    << "a Reference whose sourceNodeId names no Node on this Server shall be refused; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "the same Reference from a source that does exist shall be accepted, or the refusal above proves "
       "nothing; got "
    << to_string(resp.results()[1]);

  // Nothing was created to hold the refused Reference.
  auto sourceRead =
    mSession->attributes().try_read_sync(read_value(phantomSourceId, AttributeId::BrowseName));
  ASSERT_THAT(sourceRead, Good());
  auto sourceResp = std::move(sourceRead).value();
  ASSERT_EQ(sourceResp.results().size(), 1u);
  EXPECT_THAT(sourceResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "a refused AddReferences shall not conjure a Node to hang the Reference from";
}

// Part 4 section 5.7.3: `targetNodeClass` is a validation input, not a hint - when the TargetNode is local
// and resolvable the server must check the supplied class against the Node's actual NodeClass and refuse a
// mismatch. It matters because Browse answers `nodeClass` out of the reference rather than out of the
// target, so a reference that lies about its target's class makes every NodeClass-filtered Browse return
// a Node the client will never look at again. A plausible implementation treats the field as metadata to
// be stored, which is exactly the shape that produces the lie. The second item is the control - the same
// reference with the class it really has - so a pass cannot come from AddReferences failing wholesale,
// and each outcome is checked against what it left in the address space.
// @verifies AC-SVR-NM-AR-002-TARGETNODECLASS-MATCHES
TEST_F(ComplianceAddReferencesParameterValidation, ATargetNodeClassThatDisagreesWithTheTargetIsRefused)
{
  const auto misdeclaredId = NodeId{mNamespaceIndex, uint32_t{9960}};
  const auto correctlyDeclaredId = NodeId{mNamespaceIndex, uint32_t{9961}};

  // Both targets are Objects, seeded directly into the address space and attached to nothing, so the
  // only way either can appear beneath the test folder is the AddReferences under test.
  auto addressSpace = mServer->address_space();
  {
    auto creation = addressSpace.try_create_node_sync(misdeclaredId, NodeClass::Object, {});
    ASSERT_TRUE(creation.is_good()) << "the fixture could not seed the misdeclared target: "
                                    << to_string(creation.status_code());
    auto node = creation.value();
    node.set_browse_name(QualifiedName{mNamespaceIndex, "MisdeclaredTarget"});
    node.set_display_name(LocalizedText{"", "MisdeclaredTarget"});
  }
  {
    auto creation = addressSpace.try_create_node_sync(correctlyDeclaredId, NodeClass::Object, {});
    ASSERT_TRUE(creation.is_good()) << "the fixture could not seed the control target: "
                                    << to_string(creation.status_code());
    auto node = creation.value();
    node.set_browse_name(QualifiedName{mNamespaceIndex, "CorrectlyDeclaredTarget"});
    node.set_display_name(LocalizedText{"", "CorrectlyDeclaredTarget"});
  }

  // The target really is resolvable and really is an Object, read back over the wire - without this the
  // mismatch below would be a mismatch with nothing.
  auto classRead = mSession->attributes().try_read_sync(read_value(misdeclaredId, AttributeId::NodeClass));
  ASSERT_THAT(classRead, Good());
  auto classResp = std::move(classRead).value();
  ASSERT_EQ(classResp.results().size(), 1u);
  ASSERT_THAT(classResp.results()[0], Good()) << "the seeded target must be locally resolvable";
  ASSERT_FALSE(classResp.results()[0].value().empty()) << "the seeded target must report a NodeClass";

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, misdeclaredId)
      .target_node_class(NodeClass::Variable)  // Wrong - the target is an Object.
      .add_reference_async(mParentFolderId, NodeId{ReferenceTypeId::Organizes}, correctlyDeclaredId)
      .target_node_class(NodeClass::Object));  // Right - the control.
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_TRUE(resp.results()[0].is_bad())
    << "a targetNodeClass that disagrees with a locally resolvable target shall be refused; got "
    << to_string(resp.results()[0]);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeClassInvalid))
    << "the refusal shall carry BadNodeClassInvalid; got " << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "the same reference with the class the target really has shall be accepted, or the refusal "
       "above proves nothing; got "
    << to_string(resp.results()[1]);

  // Each outcome is checked against the address space: the misdeclared reference shall not exist, the
  // control shall.
  auto parentBrowse = mSession->view().try_browse_sync(browse(mParentFolderId));
  ASSERT_THAT(parentBrowse, Good());
  auto parentResp = std::move(parentBrowse).value();
  ASSERT_EQ(parentResp.results().size(), 1u);
  ASSERT_THAT(parentResp.results()[0], Good());
  ASSERT_FALSE(parentResp.results()[0].references().empty())
    << "the parent exposes no references at all - the checks below would be vacuous";

  bool controlFound = false;
  for (const auto& ref : parentResp.results()[0].references())
  {
    if (!ref.is_forward())
      continue;
    EXPECT_NE(ref.node_id().node_id(), misdeclaredId)
      << "a refused AddReferences shall create no reference, and least of all one whose Browse result "
         "reports a NodeClass its target does not have";
    if (ref.node_id().node_id() == correctlyDeclaredId)
      controlFound = true;
  }
  EXPECT_TRUE(controlFound) << "the correctly declared reference shall be visible in Browse";
}

// ===========================================================================
// DeleteNodes / AddNodes - obligations whose observable is what the address space holds afterwards.
// ===========================================================================

// Bad_NodeIdUnknown is an *operation-level* result: a nodesToDelete entry naming a well-formed NodeId
// that no Node holds fails in its own slot while the rest of the batch proceeds. That is what makes a
// retry after a partial failure safe - a cleanup that re-names an already-deleted Node must still
// remove everything else it names. Two plausible implementations break it in opposite directions: one
// abandons the batch on the first unresolvable item, so the Node that does exist survives; the other
// reports Good for a delete of nothing, telling the caller it removed a Node that was never there.
// Both slots and both after-states are asserted, and the order puts the unknown item first so a
// short-circuiting implementation cannot pass by accident.
// Part 4 section 5.7.4.3 - Bad_NodeIdUnknown: node id does not exist, reported per operation.
// @verifies AC-SVR-NM-DN-021-NODEIDUNKNOWN
TEST_F(ComplianceNodeManagement, DeletingAnUnknownNodeFailsOnlyItsOwnSlot)
{
  const auto existingId = NodeId{mNamespaceIndex, uint32_t{9970}};
  const auto unknownId = NodeId{mNamespaceIndex, uint32_t{9971}};

  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_variable(QualifiedName{mNamespaceIndex, "SurvivesTheBatch"}, existingId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good())
      << "the Node to be deleted must exist, or this test proves nothing";
  }

  // The unknown Node is named first: an implementation that stops at the first failure would leave the
  // second item undone, which is exactly what the per-operation rule forbids.
  auto result = mSession->node_management().try_delete_nodes_sync(delete_nodes({unknownId, existingId}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdUnknown))
    << "deleting a NodeId no Node holds shall return BadNodeIdUnknown rather than be treated as Good; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "the Node that does exist shall still be deleted when a neighbouring item names an unknown one; got "
    << to_string(resp.results()[1]);

  auto readResult = mSession->attributes().try_read_sync(read_value(existingId, AttributeId::BrowseName));
  ASSERT_THAT(readResult, Good());
  auto readResp = std::move(readResult).value();
  ASSERT_EQ(readResp.results().size(), 1u);
  EXPECT_THAT(readResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "the Node whose delete reported Good shall be gone from the address space";
}

// AC-SVR-NM-AN-004-REFERENCETYPE-NUMERIC-ID has no test here, and cannot have one at this boundary.
// The criterion reads the NodeId the server assigns to a ReferenceType Node added with no
// `requestedNewNodeId`, but AddNodes id allocation is delegate-owned: `NodeManagementService` never
// picks a NodeId, and the SDK's only allocator (`InstantiationOptions::nodeIdAllocator`, whose default
// emits *string* ids) is reached solely by `InstantiationService`, which handles Object and Variable
// items and not ReferenceType ones. The id under assertion would therefore be chosen a few hundred
// lines above by `BasicNodeManagementDelegate`, which builds it as `NodeId{namespaceIndex, counter}` -
// numeric by construction, so `is_numeric()` could not come back false whatever the SDK did. The parent
// requirement agrees the observable is not the SDK's: SVR-NM-AN-004 is a non-normative SHOULD whose
// design coverage is "Documented in deployment guide; no server enforcement".

// The children a TypeDefinition declares are created by the server, unasked, when the instance is
// added - so the server is the only party that knows they exist and the only one that can remove them.
// Cascading the delete is a *may* and the spec adds that the behaviour is Server-specific, so a child
// that outlives its parent is not by itself a defect: both "gone with it" and "still there and still
// reachable" are permitted. The outcome neither permits is the third one - the child survives with no
// inbound hierarchical Reference left, invisible to every browse and holding a NodeId no client has,
// which makes it undeletable as well as unreachable and leaks a subtree per instance lifetime. Each
// surviving child is therefore browsed inverse over HierarchicalReferences and only an empty result is
// counted against the server. The child list is read out of the instance the server actually built
// rather than hard-coded, so it cannot drift from the type it checks, and is asserted non-empty first
// because a type that instantiated nothing would make the check vacuous.
// Part 4 section 5.7.4.1 - Servers may delete additional Nodes like child Nodes that exist based on a
// TypeDefinition.
// @verifies AC-SVR-NM-DN-001-CASCADE-DELETE
TEST_F(ComplianceNodeManagement, DeletingATypedInstanceLeavesNoUnreachableChildBehind)
{
  const auto instanceId = NodeId{mNamespaceIndex, uint32_t{9975}};

  auto addResult = mSession->node_management().try_add_nodes_sync(
    AddNodesBuilder()
      .add_node(mParentFolderId, QualifiedName{mNamespaceIndex, "CascadeInstance"}, NodeClass::Object)
      .reference_type(NodeId{ReferenceTypeId::Organizes})
      .requested_node_id(instanceId)
      .type_definition(NodeId{ObjectTypeId::FileType}));
  ASSERT_THAT(addResult, Good()) << "Service-level should succeed";
  auto addResp = std::move(addResult).value();
  ASSERT_EQ(addResp.results().size(), 1u);
  ASSERT_THAT(addResp.results()[0], Good())
    << "the typed instance must be created, or this test proves nothing";

  // The children to check are read out of the instance the server actually built.
  auto instanceBrowse = mSession->view().try_browse_sync(browse(instanceId));
  ASSERT_THAT(instanceBrowse, Good());
  auto instanceResp = std::move(instanceBrowse).value();
  ASSERT_EQ(instanceResp.results().size(), 1u);
  ASSERT_THAT(instanceResp.results()[0], Good());

  std::vector<std::pair<NodeId, std::string>> typeCreatedChildren;
  for (const auto& ref : instanceResp.results()[0].references())
  {
    if (!ref.is_forward())
      continue;
    if (ref.reference_type_id() == NodeId{ReferenceTypeId::HasTypeDefinition})
      continue;  // The type itself is not a child of the instance.
    const auto childId = ref.node_id().node_id();
    if (childId.namespace_index() != mNamespaceIndex)
      continue;  // Shared NS0 Nodes (modelling rules and the like) are not the instance's to delete.
    typeCreatedChildren.emplace_back(childId, std::string{ref.browse_name().name()});
  }
  ASSERT_FALSE(typeCreatedChildren.empty())
    << "the instance the server built declares no children of its own, so the deletion check below would "
       "be vacuous - the instantiation, not the delete, is at fault";

  auto deleteResult = mSession->node_management().try_delete_nodes_sync(delete_node(instanceId));
  ASSERT_THAT(deleteResult, Good()) << "Service-level should succeed";
  auto deleteResp = std::move(deleteResult).value();
  ASSERT_EQ(deleteResp.results().size(), 1u);
  ASSERT_TRUE(deleteResp.results()[0].is_good())
    << "deleting the instance must succeed before its children can be checked; got "
    << to_string(deleteResp.results()[0]);

  const auto hierarchical = NodeId{ReferenceTypeId::HierarchicalReferences};

  std::size_t orphans = 0;
  std::string firstOrphan;
  for (const auto& child : typeCreatedChildren)
  {
    auto childRead = mSession->attributes().try_read_sync(read_value(child.first, AttributeId::BrowseName));
    ASSERT_THAT(childRead, Good());
    auto childResp = std::move(childRead).value();
    ASSERT_EQ(childResp.results().size(), 1u);
    const auto childStatus = childResp.results()[0].status().value_or(StatusCode{Status::Good});
    if (childStatus.is_bad())
      continue;  // Removed with its parent - the cascade the *may* permits.

    // The child outlived its parent, which the *may* also permits - but only while it is still part of
    // the hierarchy. Something must still point at it hierarchically, or nothing can reach it.
    auto inbound = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                      .browse(child.first)
                                                      .direction(BrowseDirection::Inverse)
                                                      .reference_type(hierarchical)
                                                      .include_subtypes(true)
                                                      .build());
    ASSERT_THAT(inbound, Good());
    auto inboundResp = std::move(inbound).value();
    ASSERT_EQ(inboundResp.results().size(), 1u);
    ASSERT_THAT(inboundResp.results()[0], Good());
    if (!inboundResp.results()[0].references().empty())
      continue;  // Still attached to the hierarchy, so still reachable and still deletable.

    ++orphans;
    if (firstOrphan.empty())
      firstOrphan = child.second + " (" + to_string(child.first) + ")";
  }
  EXPECT_EQ(orphans, 0u)
    << orphans << " of " << typeCreatedChildren.size()
    << " children created by the TypeDefinition outlived the instance they belong to and lost every "
       "inbound hierarchical Reference with it; the first is "
    << firstOrphan
    << ". Nothing references them from the hierarchy and no client holds their NodeIds, so they can be "
       "neither browsed nor deleted";
}

// A subscriber has no other way to learn that the Node it monitors is gone: silence on a MonitoredItem
// is indistinguishable from a value that has not changed, so an item left un-notified reports nothing
// for the rest of the subscription's life while the client believes it is current. The obligation is
// therefore that the delete pushes a Notification carrying Bad_NodeIdUnknown to every item monitoring
// the removed Node. The initial-value notification is drained before the delete so the notification the
// test waits for can only be the one the delete produced.
// Part 4 section 5.7.4.1 - when a deleted Node is being monitored, a Notification containing
// Bad_NodeIdUnknown is sent to the monitoring Client.
// @verifies AC-SVR-NM-DN-002-MONITORED-DELETE-NOTIFIES
TEST_F(ComplianceNodeManagement, DeletingAMonitoredNodeNotifiesItsSubscriberThatTheNodeIsGone)
{
  const auto monitoredId = NodeId{mNamespaceIndex, uint32_t{9980}};

  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_variable(QualifiedName{mNamespaceIndex, "MonitoredNode"}, monitoredId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "the Node to monitor must exist, or this test proves nothing";
  }

  auto subscription = create_subscription_with_monitored_item(
    *mSession, monitoredId, {.publishingInterval = 50.0}, {.clientHandle = 77u, .samplingInterval = 50.0});
  ASSERT_NE(subscription.subscriptionId, 0u) << "the subscription must exist for the delete to notify it";
  ASSERT_NE(subscription.monitoredItemId, 0u) << "the monitored item must exist for the delete to notify it";

  // Drain the initial-value DataChange so the notification waited for below can only be the delete's.
  drain_initial_publish(*mSession, subscription.subscriptionId);

  {
    auto result = mSession->node_management().try_delete_nodes_sync(delete_node(monitoredId));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_TRUE(resp.results()[0].is_good())
      << "the monitored Node must actually be deleted before its subscriber can be told so; got "
      << to_string(resp.results()[0]);
  }

  auto notification = wait_for_data_change(
    *mSession,
    subscription.subscriptionId,
    [](const DataChangeNotification& change)
    {
      for (const auto& item : change.monitored_items())
      {
        const auto status = item.value().status();
        if (status.has_value() && status->as_status() == Status::BadNodeIdUnknown)
          return true;
      }
      return false;
    },
    std::chrono::seconds{3});

  ASSERT_TRUE(notification.has_value())
    << "no Notification carrying BadNodeIdUnknown reached the subscriber within 3s of the Node being "
       "deleted; the MonitoredItem is stranded and the Client has no way to learn its Node is gone";

  std::size_t matching = 0;
  for (const auto& item : notification->monitored_items())
  {
    const auto status = item.value().status();
    if (status.has_value() && status->as_status() == Status::BadNodeIdUnknown)
    {
      ++matching;
      EXPECT_EQ(item.client_handle(), 77u)
        << "the Notification shall be delivered against the client handle of the item that monitored the "
           "deleted Node; got "
        << item.client_handle();
    }
  }
  EXPECT_EQ(matching, 1u) << "exactly one MonitoredItem monitored the deleted Node, so exactly one "
                             "BadNodeIdUnknown Notification is expected; got "
                          << matching;
}

// ===========================================================================
// Node management - the per-item authorization gate.
//
// Every fixture above gives the Anonymous Role broad namespace defaults. These tests override
// RolePermissions on individual Nodes to create batches in which one item is permitted and its neighbour
// is not.
// ===========================================================================

class ComplianceNodeManagementPerItemAuthz : public ComplianceNodeManagement
{
protected:
  /// Records that this session holds no permission to perform @p operation on @p nodeId.
  void deny(ua::server::AccessOperation operation, const NodeId& nodeId)
  {
    auto [entry, inserted] = mNodePermissions.try_emplace(nodeId, all_node_management_permissions());
    static_cast<void>(inserted);
    switch (operation)
    {
    case AccessOperation::Browse:
      entry->second.reset(PermissionType::Bit::Browse);
      break;
    case AccessOperation::Read:
      entry->second.reset(PermissionType::Bit::Read);
      break;
    case AccessOperation::Write:
      entry->second.reset(PermissionType::Bit::Write);
      break;
    case AccessOperation::AddReferences:
      entry->second.reset(PermissionType::Bit::AddReference);
      break;
    case AccessOperation::DeleteNodes:
      entry->second.reset(PermissionType::Bit::DeleteNode);
      break;
    default:
      ADD_FAILURE() << "unsupported access-operation mapping in the test fixture";
      return;
    }

    RolePermissionType permissions;
    permissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    permissions.permissions() = entry->second;
    mServer->address_space().find_node_sync(nodeId).set_role_permissions(
      std::vector<RolePermissionType>{permissions});
  }

  std::unordered_map<NodeId, PermissionType> mNodePermissions;
};

// The permission is checked per item and scoped on the source Node, because a Reference is stored on
// its source: permission to add one is permission to modify that Node. A plausible implementation gates
// the request rather than the item and fails the whole batch on the first denial, which turns an
// authorization decision about one Node into a denial of service for every other Node in the request;
// the mirror-image implementation checks the session once at activation and lets every item through.
// Both are refuted by driving one permitted and one denied item in a single request and asserting each
// slot separately, together with what each left in the address space - a denial that still created the
// Reference would be the worst outcome of all.
// Part 4 section 5.7.3.3 - Bad_UserAccessDenied: user does not have permission, reported per operation.
// @verifies AC-SVR-NM-AR-027-ADDREFERENCES-DENIED
TEST_F(ComplianceNodeManagementPerItemAuthz, AddReferencesRefusesOnlyTheItemTheUserMayNotAdd)
{
  const auto permittedSourceId = NodeId{mNamespaceIndex, uint32_t{9985}};
  const auto deniedSourceId = NodeId{mNamespaceIndex, uint32_t{9986}};
  const auto targetId = NodeId{mNamespaceIndex, uint32_t{9987}};

  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_object(QualifiedName{mNamespaceIndex, "PermittedSource"}, permittedSourceId));
    req.nodes_to_add().push_back(
      make_add_object(QualifiedName{mNamespaceIndex, "DeniedSource"}, deniedSourceId));
    req.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "SharedTarget"}, targetId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 3u);
    ASSERT_THAT(resp.results()[0], Good()) << "the permitted source must exist";
    ASSERT_THAT(resp.results()[1], Good()) << "the denied source must exist";
    ASSERT_THAT(resp.results()[2], Good()) << "the shared target must exist";
  }

  // The session may modify one of the two sources and not the other.
  deny(AccessOperation::AddReferences, deniedSourceId);

  auto result = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder()
      .add_reference_async(deniedSourceId, NodeId{ReferenceTypeId::Organizes}, targetId)
      .add_reference_async(permittedSourceId, NodeId{ReferenceTypeId::Organizes}, targetId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadUserAccessDenied))
    << "a Reference the session has no permission to add shall return BadUserAccessDenied in its own "
       "slot; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "an item the session is permitted to perform shall still succeed alongside a denied one; got "
    << to_string(resp.results()[1]);

  // The denial is only meaningful if the Reference was not created anyway.
  auto deniedBrowse = mSession->view().try_browse_sync(browse(deniedSourceId));
  ASSERT_THAT(deniedBrowse, Good());
  auto deniedResp = std::move(deniedBrowse).value();
  ASSERT_EQ(deniedResp.results().size(), 1u);
  ASSERT_THAT(deniedResp.results()[0], Good());
  for (const auto& ref : deniedResp.results()[0].references())
  {
    EXPECT_NE(ref.node_id().node_id(), targetId)
      << "a denied AddReferences shall create no Reference; the target is reachable from the source the "
         "session may not modify";
  }

  // ...and the permitted item's acceptance is only meaningful if its Reference really exists.
  auto permittedBrowse = mSession->view().try_browse_sync(browse(permittedSourceId));
  ASSERT_THAT(permittedBrowse, Good());
  auto permittedResp = std::move(permittedBrowse).value();
  ASSERT_EQ(permittedResp.results().size(), 1u);
  ASSERT_THAT(permittedResp.results()[0], Good());
  ASSERT_FALSE(permittedResp.results()[0].references().empty())
    << "the permitted source exposes no references at all - the check below would be vacuous";

  bool permittedReferenceFound = false;
  for (const auto& ref : permittedResp.results()[0].references())
  {
    if (ref.node_id().node_id() == targetId)
      permittedReferenceFound = true;
  }
  EXPECT_TRUE(permittedReferenceFound)
    << "the Reference the session was permitted to add shall be visible in Browse";
}

// The same per-item rule on DeleteNodes, where getting it wrong is destructive rather than merely
// obstructive: an implementation that authorizes the request as a whole and then deletes every item it
// was given removes the Node the session had no permission to touch, and no later check can undo it.
// The denied Node is named first so a batch that abandons on the first denial would leave the permitted
// Node behind, and both after-states are read back - the permitted Node gone, the denied Node intact.
// Part 4 section 5.7.4.3 - Bad_UserAccessDenied: user does not have permission, reported per operation.
// @verifies AC-SVR-NM-DN-022-DELETENODES-DENIED
TEST_F(ComplianceNodeManagementPerItemAuthz, DeleteNodesRefusesOnlyTheNodeTheUserMayNotDelete)
{
  const auto permittedId = NodeId{mNamespaceIndex, uint32_t{9990}};
  const auto deniedId = NodeId{mNamespaceIndex, uint32_t{9991}};

  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_variable(QualifiedName{mNamespaceIndex, "MayBeDeleted"}, permittedId));
    req.nodes_to_add().push_back(
      make_add_variable(QualifiedName{mNamespaceIndex, "MayNotBeDeleted"}, deniedId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 2u);
    ASSERT_THAT(resp.results()[0], Good()) << "the deletable Node must exist";
    ASSERT_THAT(resp.results()[1], Good()) << "the protected Node must exist";
  }

  deny(AccessOperation::DeleteNodes, deniedId);

  auto result = mSession->node_management().try_delete_nodes_sync(delete_nodes({deniedId, permittedId}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadUserAccessDenied))
    << "deleting a Node the session has no permission to delete shall return BadUserAccessDenied in its "
       "own slot; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[1].is_good())
    << "a Node the session may delete shall still be deleted alongside a denied one; got "
    << to_string(resp.results()[1]);

  auto deniedRead = mSession->attributes().try_read_sync(read_value(deniedId, AttributeId::BrowseName));
  ASSERT_THAT(deniedRead, Good());
  auto deniedResp = std::move(deniedRead).value();
  ASSERT_EQ(deniedResp.results().size(), 1u);
  EXPECT_THAT(deniedResp.results()[0], Good())
    << "the Node whose deletion was denied shall still exist; a denial that deleted it anyway cannot be "
       "undone";

  auto permittedRead = mSession->attributes().try_read_sync(read_value(permittedId, AttributeId::BrowseName));
  ASSERT_THAT(permittedRead, Good());
  auto permittedResp = std::move(permittedRead).value();
  ASSERT_EQ(permittedResp.results().size(), 1u);
  EXPECT_THAT(permittedResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "the Node the session was permitted to delete shall be gone";
}

// Two different reasons a delete is refused, and the caller's remedy differs by reason: an
// authenticated user who simply holds no permission on the Node should authenticate differently, while
// a Node the deployment protects from deletion will refuse every user equally and re-authenticating is
// wasted effort. Collapsing the two codes onto one destroys that distinction, which is why the two
// stimuli are driven side by side in a single request. The premises are established first - the
// protected Node reads back Good while the forbidden one refuses a Read, so the two really are in
// different positions - and then the two result codes are required to differ.
// Part 4 section 5.7.4.3 - Bad_NoDeleteRights: no permission to delete, distinct from Bad_UserAccessDenied.
// @verifies AC-SVR-NM-DN-023-NODELETERIGHTS
// The execution-evidence reader requires the full TEST_F identity on one line.
// clang-format off
TEST_F(ComplianceNodeManagementPerItemAuthz, ANodeProtectedFromDeletionIsReportedDistinctlyFromOneTheUserMayNotTouch)
// clang-format on
{
  const auto protectedId = NodeId{mNamespaceIndex, uint32_t{9993}};
  const auto forbiddenId = NodeId{mNamespaceIndex, uint32_t{9994}};

  {
    AddNodesRequest req;
    req.nodes_to_add().push_back(
      make_add_variable(QualifiedName{mNamespaceIndex, "UndeletableNode"}, protectedId));
    req.nodes_to_add().push_back(
      make_add_variable(QualifiedName{mNamespaceIndex, "UntouchableNode"}, forbiddenId));
    auto result = mSession->node_management().try_add_nodes_sync(std::move(req));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 2u);
    ASSERT_THAT(resp.results()[0], Good()) << "the delete-protected Node must exist";
    ASSERT_THAT(resp.results()[1], Good()) << "the inaccessible Node must exist";
  }

  // The first Node is one the session may read and write but the deployment will not let anyone delete.
  mHandler->protectedNodeIds.insert(protectedId);
  // The second is one the session cannot touch at all. Browse is the permission that has to be withheld
  // for that to be true of an Attribute other than Value: Part 3 section 8.55 Table 37 makes Read (bit 5)
  // valid for Variables only and gating the Value Attribute alone, while Browse (bit 0) is what lets a Client
  // "Read Attributes other than the Value or the RolePermissions Attribute". A Read of BrowseName
  // therefore consults Browse, and denying Read alone would leave it permitted.
  deny(AccessOperation::Browse, forbiddenId);
  deny(AccessOperation::Read, forbiddenId);
  deny(AccessOperation::Write, forbiddenId);
  deny(AccessOperation::DeleteNodes, forbiddenId);

  // The premise: the two Nodes really are in different positions as far as this session is concerned.
  auto protectedRead = mSession->attributes().try_read_sync(read_value(protectedId, AttributeId::BrowseName));
  ASSERT_THAT(protectedRead, Good());
  auto protectedReadResp = std::move(protectedRead).value();
  ASSERT_EQ(protectedReadResp.results().size(), 1u);
  EXPECT_THAT(protectedReadResp.results()[0], Good())
    << "the delete-protected Node is one the session may read; without that the contrast below is not "
       "the contrast the obligation draws";

  auto forbiddenRead = mSession->attributes().try_read_sync(read_value(forbiddenId, AttributeId::BrowseName));
  ASSERT_THAT(forbiddenRead, Good());
  auto forbiddenReadResp = std::move(forbiddenRead).value();
  ASSERT_EQ(forbiddenReadResp.results().size(), 1u);
  EXPECT_THAT(forbiddenReadResp.results()[0], HasStatusPresent(Status::BadUserAccessDenied))
    << "the inaccessible Node is one the session may not even read; without that the contrast below is "
       "not the contrast the obligation draws";

  auto result = mSession->node_management().try_delete_nodes_sync(delete_nodes({protectedId, forbiddenId}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNoDeleteRights))
    << "a Node the session may access but which is protected from deletion shall return "
       "BadNoDeleteRights, not BadUserAccessDenied; got "
    << to_string(resp.results()[0]);
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadUserAccessDenied))
    << "a Node the session has no permission on shall return BadUserAccessDenied; got "
    << to_string(resp.results()[1]);
  EXPECT_NE(to_string(resp.results()[0]), to_string(resp.results()[1]))
    << "the two refusals carry the same code, so a caller cannot tell 'authenticate differently' from "
       "'this Node cannot be deleted by anyone': both read "
    << to_string(resp.results()[0]);

  // Neither refusal may have deleted anything.
  auto protectedAfter =
    mSession->attributes().try_read_sync(read_value(protectedId, AttributeId::BrowseName));
  ASSERT_THAT(protectedAfter, Good());
  auto protectedAfterResp = std::move(protectedAfter).value();
  ASSERT_EQ(protectedAfterResp.results().size(), 1u);
  EXPECT_THAT(protectedAfterResp.results()[0], Good())
    << "the delete-protected Node shall survive the refused delete";
}

// ===========================================================================
// DeleteNodes - the outcome that is neither a success nor a failure.
//
// `BasicNodeManagementDelegate` at the top of this file hands every delete straight to
// `AddressSpace::try_delete_node_sync`, so no test on that fixture can put a Node into the one state
// this obligation is about: removed, while References held by its TargetNodes that the deployment could
// not clear are left behind. The delegate below states that deployment condition directly - it deletes
// the Node and then reports the Uncertain code for the Nodes the test nominates. Reporting the code is
// delegate-owned by design; what a test on this fixture observes is the SDK's half of the obligation,
// which is that `NodeManagementService` and the wire carry an Uncertain per-item status back to the
// client without normalising it, and that the `deleteTargetReferences` flag the code is about reaches
// the delegate as the client wrote it.
// ===========================================================================

class ReferenceNotDeletedDelegate final : public NodeManagementDelegate
{
public:
  /// Nodes this deployment can remove but whose target-side References it cannot all clear.
  std::unordered_set<NodeId> nodesWithUnclearableReferences;

  /// Every item the delegate was handed, as (NodeId, deleteTargetReferences). Written on the server
  /// thread while the request under test is being served and read only once its response has arrived,
  /// read only once its response has arrived.
  std::vector<std::pair<NodeId, bool>> itemsSeen;

  void add_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<NodeManagementDelegate::AuthorizedAddNode> items,
    NodeManagementDelegate::AddNodesCompleteCallback callback) override
  {
    BatchResult<NodeManagementDelegate::AddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (std::size_t i = 0; i < items.size(); ++i)
    {
      AddNodesResult result;
      result.status_code() = Status::BadServiceUnsupported;
      batch.items.emplace_back(std::move(result));
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<AddReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    callback(delete_delegate_unsupported(items.size()));
  }

  void delete_nodes_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteNodesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    BatchResult<VoidResult> batch;
    batch.items.reserve(items.size());

    for (auto& item : items)
    {
      itemsSeen.emplace_back(item.node_id(), item.delete_target_references());

      auto deleteResult = addressSpace.try_delete_node_sync(item.node_id(),
        item.delete_target_references(),
        item.delete_target_references() ? ReferenceHalves::Both : ReferenceHalves::ThisHalfOnly);
      if (deleteResult.is_bad())
      {
        batch.items.emplace_back(VoidResult{deleteResult.status_code()});
        continue;
      }

      // The Node itself is gone either way. What differs is whether the References that pointed at it
      // went with it, and that is the only thing the Uncertain code reports.
      if (nodesWithUnclearableReferences.count(item.node_id()) > 0)
        batch.items.emplace_back(VoidResult{StatusCode{Status::UncertainReferenceNotDeleted}});
      else
        batch.items.emplace_back(VoidResult{});
    }

    callback(std::move(batch));
  }

  void delete_references_async(std::shared_ptr<const NodeManagementDelegate::Context> context,
    AddressSpace addressSpace, std::vector<DeleteReferencesItem> items,
    NodeManagementDelegate::NodeMgmtCompleteCallback callback) override
  {
    callback(delete_delegate_unsupported(items.size()));
  }

private:
  /// The tests on this fixture only exercise DeleteNodes; the other operations are not implemented.
  static BatchResult<VoidResult> delete_delegate_unsupported(std::size_t count)
  {
    BatchResult<VoidResult> batch;
    batch.items.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
      batch.items.emplace_back(VoidResult{StatusCode{Status::BadServiceUnsupported}});
    }
    return batch;
  }
};

class ComplianceDeleteNodesUncertainOutcome : public ComplianceNodeManagement
{
protected:
  void SetUp() override
  {
    ComplianceNodeManagement::SetUp();
    ASSERT_TRUE(mServer.has_value());
    mUncertainHandler = std::make_shared<ReferenceNotDeletedDelegate>();
    mServer->set_node_management_delegate(ua::test::offloaded(mUncertainHandler));
  }

  /// Seeds a Node directly into the address space and hangs it beneath the test folder, so it carries an
  /// inbound Reference for the delete to try to clear. AddNodes reports BadServiceUnsupported on this
  /// fixture's delegate, so Nodes cannot be created over the wire.
  void seed_child_node(const NodeId& nodeId, const char* browseName)
  {
    auto addressSpace = mServer->address_space();
    auto creation = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
    ASSERT_TRUE(creation.is_good()) << "the fixture could not seed " << browseName << ": "
                                    << to_string(creation.status_code());
    auto node = creation.value();
    node.set_browse_name(QualifiedName{mNamespaceIndex, browseName});
    node.set_display_name(LocalizedText{"", browseName});

    auto folder = addressSpace.find_node_sync(mParentFolderId);
    folder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, nodeId);
  }

  std::shared_ptr<ReferenceNotDeletedDelegate> mUncertainHandler;
};

// The severity is the whole content of this code. The Node is gone, so Bad would report a failure to a
// caller whose delete in fact succeeded and would invite a retry against a NodeId nothing holds any
// more; References to it are still out there, so Good would hide targets that Browse will keep handing
// out and that no later request will ever name. Uncertain is the only report true of both halves, and a
// plausible service implementation loses it in one step - `Result<void>` converts to bool as
// `is_good()`, so any layer that sorts per-item outcomes into "succeeded" and "failed" flattens the
// Uncertain onto one side before the client sees it. A second Node whose delete leaves nothing behind
// travels in the same request as the control, so a server that answered Uncertain to every delete could
// not pass, and the deleted Node is read back afterwards because an Uncertain that left the Node in
// place would be a delete that failed and should have said Bad.
// Part 4 section 5.7.4.3 - Uncertain_ReferenceNotDeleted: the Server was not able to delete all target
// references.
// @verifies AC-SVR-NM-DN-024-UNCERTAIN-REFERENCE-NOT-DELETED
TEST_F(ComplianceDeleteNodesUncertainOutcome, APartiallyCompletedDeleteIsReportedAsUncertainNotGoodOrBad)
{
  const auto unclearableId = NodeId{mNamespaceIndex, uint32_t{9765}};
  const auto clearableId = NodeId{mNamespaceIndex, uint32_t{9766}};

  ASSERT_NO_FATAL_FAILURE(seed_child_node(unclearableId, "NodeWithUnclearableReferences"));
  ASSERT_NO_FATAL_FAILURE(seed_child_node(clearableId, "NodeWhoseReferencesAllClear"));

  // The premise: the Node is there to begin with, so "gone afterwards" says something.
  {
    auto before = mSession->attributes().try_read_sync(read_value(unclearableId, AttributeId::BrowseName));
    ASSERT_THAT(before, Good());
    auto beforeResp = std::move(before).value();
    ASSERT_EQ(beforeResp.results().size(), 1u);
    ASSERT_THAT(beforeResp.results()[0], Good())
      << "the Node to be deleted must exist, or this test proves nothing";
  }

  // The deployment condition the code exists to report: this Node can be removed, but the References
  // its TargetNodes hold cannot all be cleared with it.
  mUncertainHandler->nodesWithUnclearableReferences.insert(unclearableId);

  auto result =
    mSession->node_management().try_delete_nodes_sync(delete_nodes({unclearableId, clearableId}, true));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  // The stimulus is only the stimulus if the request asked for the target-side References to go too.
  bool itemSeen = false;
  bool flagAsWritten = false;
  for (const auto& seen : mUncertainHandler->itemsSeen)
  {
    if (seen.first != unclearableId)
      continue;
    itemSeen = true;
    flagAsWritten = seen.second;
  }
  ASSERT_TRUE(itemSeen) << "the delete never reached the delegate that reports this condition, so nothing "
                           "below is about the obligation; "
                        << mUncertainHandler->itemsSeen.size() << " items arrived";
  EXPECT_TRUE(flagAsWritten)
    << "the client wrote deleteTargetReferences TRUE and it shall arrive that way; an Uncertain about "
       "target-side References cannot arise from a request that never asked for them to be removed";

  EXPECT_THAT(resp.results()[0], HasStatus(Status::UncertainReferenceNotDeleted))
    << "a delete that removed the Node but could not clear every target-side Reference shall report "
       "Uncertain_ReferenceNotDeleted; got "
    << to_string(resp.results()[0]);
  EXPECT_TRUE(resp.results()[0].is_uncertain())
    << "the severity is the content - Bad would deny a delete that succeeded and Good would hide the "
       "References left dangling; the slot carries "
    << to_string(resp.results()[0]);

  EXPECT_TRUE(resp.results()[1].is_good())
    << "a delete that left nothing behind shall be Good, or the Uncertain above is merely what this "
       "server says about every delete; got "
    << to_string(resp.results()[1]);

  // Bad would be the wrong severity, because the Node really did go.
  auto after = mSession->attributes().try_read_sync(read_value(unclearableId, AttributeId::BrowseName));
  ASSERT_THAT(after, Good());
  auto afterResp = std::move(after).value();
  ASSERT_EQ(afterResp.results().size(), 1u);
  EXPECT_THAT(afterResp.results()[0], HasStatusPresent(Status::BadNodeIdUnknown))
    << "the Node whose delete reported Uncertain shall nevertheless be gone; an Uncertain that left the "
       "Node in place is a delete that failed and should have said Bad";
}

// Part 3 section 5.4 forbids the Server Object's membership of a View, not a Reference to it, and Part 4
// section 5.7.3.4 names no status for such an add. NR-41: the Reference is stored as any other is, and the
// Browse service still keeps the Server Object out of the View; the final Browse is that control.
class ViewReferences : public ComplianceNodeManagement
{};

// @relation(AC-SVR-EVT-ATTR-007-VIEW-REFERENCE-TO-SERVER-OBJECT-STORED, scope=function)
TEST_F(ViewReferences, AReferenceFromAViewToTheServerObjectIsStored)
{
  auto addressSpace = mServer->address_space();
  const NodeId viewId{mNamespaceIndex, uint32_t{9700}};
  const NodeId serverObject{ObjectId::Server};
  auto viewNode = addressSpace.create_node_sync(viewId, NodeClass::View);
  viewNode.set_browse_name(QualifiedName{mNamespaceIndex, "ViewReferencingTheServer"});
  viewNode.set_display_name(LocalizedText{"", "ViewReferencingTheServer"});
  auto view = viewNode.as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(NodeId{ObjectId::ObjectsFolder}).is_good());

  auto added = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder().add_reference_async(viewId, NodeId{ReferenceTypeId::Organizes}, serverObject));
  ASSERT_THAT(added, Good());
  ASSERT_EQ(added.value().results().size(), 1u);
  EXPECT_THAT(added.value().results()[0], HasStatus(Status::Good))
    << "an Organizes Reference from a View Node to the Server Object was refused";

  auto withoutView = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                        .browse(viewId)
                                                        .direction(BrowseDirection::Forward)
                                                        .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                        .include_subtypes(false));
  ASSERT_THAT(withoutView, Good());
  ASSERT_EQ(withoutView.value().results().size(), 1u);
  bool referencesTheServer = false;
  for (const auto& reference : withoutView.value().results().payload()[0].references().payload())
    referencesTheServer = referencesTheServer || reference.node_id().node_id() == serverObject;
  EXPECT_TRUE(referencesTheServer) << "the stored Reference to the Server Object is not returned";

  auto inView = mSession->view().try_browse_sync(
    BrowseRequestBuilder().view(viewId).browse(serverObject).direction(BrowseDirection::Forward));
  ASSERT_THAT(inView, Good());
  ASSERT_EQ(inView.value().results().size(), 1u);
  EXPECT_EQ(inView.value().results().payload()[0].status_code().as_status(), Status::BadNodeNotInView)
    << "storing the Reference put the Server Object in the View";
}

// Part 3 section 5.4, Table 10, ViewVersion: "When Nodes are added to or removed from a View, the value of
// the ViewVersion Property is updated." Deleting a member of an in-memory View through DeleteNodes removes it
// from the View and advances the ViewVersion once by the time the deletion answers (SVR-ADDRSP-259, NR-57,
// DL-8).
class ViewVersionOnDelete : public ComplianceNodeManagement
{
protected:
  std::optional<uint32_t> read_view_version(const NodeId& versionId)
  {
    auto response = mSession->attributes().read_sync(read_value(versionId));
    if (response.results().size() != 1u ||
        (response.results()[0].status().has_value() && !response.results()[0].status()->is_good()))
    {
      ADD_FAILURE() << "the ViewVersion could not be read";
      return std::nullopt;
    }
    const auto* number = response.results()[0].value().try_as<uint32_t>();
    if (number == nullptr)
    {
      ADD_FAILURE() << "the ViewVersion is not a UInt32: " << to_string(response.results()[0].value());
      return std::nullopt;
    }
    return *number;
  }

  StatusCode browse_in_view(const NodeId& viewId, const NodeId& nodeId)
  {
    auto browsed = mSession->view().try_browse_sync(
      BrowseRequestBuilder().view(viewId).browse(nodeId).direction(BrowseDirection::Forward));
    if (browsed.is_bad() || browsed.value().results().size() != 1u)
    {
      ADD_FAILURE() << "the Browse in the View's context failed";
      return StatusCode{Status::BadInternalError};
    }
    return browsed.value().results().payload()[0].status_code();
  }
};

// A and B are members of the View; C is not. The deletion of A advances the ViewVersion once; that of C does
// not. A Node created again with A's NodeId is not in the View, and B still is.
// @relation(AC-SVR-ADDRSP-259-DELETED-MEMBER-LEAVES-VIEW, scope=function)
TEST_F(ViewVersionOnDelete, DeletingAMemberAdvancesViewVersion)
{
  auto addressSpace = mServer->address_space();
  const NodeId viewId{mNamespaceIndex, uint32_t{9720}};
  const NodeId versionId{mNamespaceIndex, uint32_t{9721}};
  const NodeId memberA{mNamespaceIndex, uint32_t{9722}};
  const NodeId memberB{mNamespaceIndex, uint32_t{9723}};
  const NodeId nonMemberC{mNamespaceIndex, uint32_t{9724}};

  auto viewNode = addressSpace.create_node_sync(viewId, NodeClass::View);
  viewNode.set_browse_name(QualifiedName{mNamespaceIndex, "VersionedView"});
  viewNode.set_display_name(LocalizedText{"", "VersionedView"});
  auto versionNode = addressSpace.create_node_sync(versionId, NodeClass::Variable);
  auto version = versionNode.as<VariableAccessor>();
  ASSERT_TRUE(version.has_value());
  version->set_browse_name(QualifiedName{0, "ViewVersion"});
  version->set_display_name(LocalizedText{"", "ViewVersion"});
  version->set_data_type(NodeId{DataTypeId::UInt32});
  AccessLevelType readable;
  readable.set(AccessLevelType::Bit::CurrentRead);
  version->set_access_level(readable);
  version->write_value_sync(DataValue{Variant{uint32_t{1}}});
  viewNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, versionId);
  versionNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, ExpandedNodeId{viewId}, false);
  versionNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
  for (const auto& [nodeId, name] :
    {std::pair{memberA, "MemberA"}, std::pair{memberB, "MemberB"}, std::pair{nonMemberC, "NonMemberC"}})
  {
    auto object = addressSpace.create_node_sync(nodeId, NodeClass::Object);
    object.set_browse_name(QualifiedName{mNamespaceIndex, name});
    object.set_display_name(LocalizedText{"", name});
  }
  auto view = viewNode.as<ViewAccessor>();
  ASSERT_TRUE(view.has_value());
  ASSERT_TRUE(view->try_add_node_to_view_sync(memberA).is_good());
  ASSERT_TRUE(view->try_add_node_to_view_sync(memberB).is_good());
  const auto before = read_view_version(versionId);
  ASSERT_TRUE(before.has_value());

  auto deletedA = mSession->node_management().try_delete_nodes_sync(delete_node(memberA));
  ASSERT_THAT(deletedA, Good());
  ASSERT_EQ(deletedA.value().results().size(), 1u);
  EXPECT_THAT(deletedA.value().results()[0], HasStatus(Status::Good));
  EXPECT_EQ(read_view_version(versionId), *before + 1u)
    << "deleting a member did not advance the ViewVersion once by the time the deletion answered";

  auto deletedC = mSession->node_management().try_delete_nodes_sync(delete_node(nonMemberC));
  ASSERT_THAT(deletedC, Good());
  ASSERT_EQ(deletedC.value().results().size(), 1u);
  EXPECT_THAT(deletedC.value().results()[0], HasStatus(Status::Good));
  EXPECT_EQ(read_view_version(versionId), *before + 1u) << "deleting a Node that is not a member advanced it";

  auto createdAgain = addressSpace.create_node_sync(memberA, NodeClass::Object);
  createdAgain.set_browse_name(QualifiedName{mNamespaceIndex, "MemberAAgain"});
  createdAgain.set_display_name(LocalizedText{"", "MemberAAgain"});
  EXPECT_EQ(browse_in_view(viewId, memberA).as_status(), Status::BadNodeNotInView)
    << "the Node created again with a deleted member's NodeId is in the View";
  EXPECT_EQ(browse_in_view(viewId, memberB).as_status(), Status::Good)
    << "the member that was not deleted is no longer browsable in the View's context";
}

// ===========================================================================
// A Node holds a Reference once (SVR-ADDRSP-260, NR-68 item 8, NR-70 F14)
// ===========================================================================

namespace
{

/// The forward References of @p node a client Browse returns for @p referenceType, as "type -> target"
/// strings.
std::vector<std::string> browse_forward(
  ua::client::Session& session, const NodeId& node, const NodeId& referenceType, bool includeSubtypes)
{
  std::vector<std::string> listed;
  auto browsed = session.view().try_browse_sync(BrowseRequestBuilder()
                                                  .browse(node)
                                                  .direction(BrowseDirection::Forward)
                                                  .reference_type(referenceType)
                                                  .include_subtypes(includeSubtypes));
  if (browsed.is_bad() || browsed.value().results().size() != 1u)
  {
    ADD_FAILURE() << "the Browse of " << to_string(node) << " failed";
    return listed;
  }
  for (const auto& reference : browsed.value().results().payload()[0].references().payload())
    listed.push_back(
      to_string(reference.reference_type_id()) + " -> " + to_string(reference.node_id().node_id()));
  std::sort(listed.begin(), listed.end());
  return listed;
}

std::string forward_ref(const NodeId& type, const NodeId& target)
{
  return to_string(type) + " -> " + to_string(target);
}

/// The inverse References of @p node a client Browse returns for @p referenceType, as "type -> target"
/// strings.
std::vector<std::string> browse_inverse(
  ua::client::Session& session, const NodeId& node, const NodeId& referenceType, bool includeSubtypes)
{
  std::vector<std::string> listed;
  auto browsed = session.view().try_browse_sync(BrowseRequestBuilder()
                                                  .browse(node)
                                                  .direction(BrowseDirection::Inverse)
                                                  .reference_type(referenceType)
                                                  .include_subtypes(includeSubtypes));
  if (browsed.is_bad() || browsed.value().results().size() != 1u)
  {
    ADD_FAILURE() << "the inverse Browse of " << to_string(node) << " failed";
    return listed;
  }
  for (const auto& reference : browsed.value().results().payload()[0].references().payload())
    listed.push_back(
      to_string(reference.reference_type_id()) + " -> " + to_string(reference.node_id().node_id()));
  std::sort(listed.begin(), listed.end());
  return listed;
}

/// Whether @p status's ErrorDetail, or one of its causes, has @p code.
bool detail_chain_has_code(const StatusCode& status, std::string_view code)
{
  for (auto detail = status.shared_detail(); detail; detail = detail->cause)
  {
    if (detail->code == code)
      return true;
  }
  return false;
}

/// Whether @p status's ErrorDetail, or one of its causes, carries @p key in its context.
bool detail_chain_has_context(const StatusCode& status, std::string_view key)
{
  for (auto detail = status.shared_detail(); detail; detail = detail->cause)
  {
    for (const auto& fact : detail->context)
    {
      if (fact.key == key)
        return true;
    }
  }
  return false;
}

}  // namespace

class ReferenceDuplicates : public ComplianceNodeManagement
{
protected:
  NodeAccessor make_object(uint32_t identifier, const char* name)
  {
    auto node =
      mServer->address_space().create_node_sync(NodeId{mNamespaceIndex, identifier}, NodeClass::Object);
    node.set_browse_name(QualifiedName{mNamespaceIndex, name});
    node.set_display_name(LocalizedText{"", name});
    return node;
  }
};

// Part 3 section 4.3.4: each Node can reference another Node with the same ReferenceType only once. The add
// to C is the control that a Reference to another target is still stored.
// @relation(AC-SVR-ADDRSP-260-REPEATED-ADD-REFUSED, scope=function)
TEST_F(ReferenceDuplicates, BrowseReturnsARepeatedlyAddedReferenceOnce)
{
  auto a = make_object(9800, "DuplicateSourceA");
  const NodeId b = make_object(9801, "DuplicateTargetB").get_node_id();
  const NodeId c = make_object(9802, "DuplicateTargetC").get_node_id();
  // HasDictionaryEntry, which the address space does not pair: a paired type's held half answers Good through
  // an accessor (NR-30 rule 4).
  const NodeId hasDictionaryEntry{ReferenceTypeId::HasDictionaryEntry};

  EXPECT_TRUE(a.try_add_reference_sync(hasDictionaryEntry, b).is_good());
  EXPECT_EQ(a.try_add_reference_sync(hasDictionaryEntry, b).status_code().as_status(),
    Status::BadDuplicateReferenceNotAllowed)
    << "a Reference the Node already holds was added again";
  EXPECT_TRUE(a.try_add_reference_sync(hasDictionaryEntry, c).is_good());

  EXPECT_EQ(browse_forward(*mSession, a.get_node_id(), hasDictionaryEntry, false),
    (std::vector<std::string>{forward_ref(hasDictionaryEntry, b), forward_ref(hasDictionaryEntry, c)}))
    << "Browse did not return each Reference once";
}

class AddReferencesIdentity : public ReferenceDuplicates
{};

// Part 3 section 4.3.4: a subtype of a concrete ReferenceType counts as its base concrete type, so a
// HasOrderedComponent beside a held HasComponent to the same target is the same Reference. Organizes is the
// control that the identity is not "any Reference to the same target".
// @relation(AC-SVR-ADDRSP-260-SUBTYPE-OF-HELD-CONCRETE-TYPE-IS-DUPLICATE, scope=function)
TEST_F(AddReferencesIdentity, AHasOrderedComponentBesideAHeldHasComponentIsRefused)
{
  auto a = make_object(9810, "ComponentSourceA");
  const NodeId b = make_object(9811, "ComponentTargetB").get_node_id();
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  const NodeId organizes{ReferenceTypeId::Organizes};
  ASSERT_TRUE(a.try_add_reference_sync(hasComponent, b).is_good());

  auto ordered =
    mSession->node_management().try_add_references_sync(AddReferencesBuilder().add_reference_async(
      a.get_node_id(), NodeId{ReferenceTypeId::HasOrderedComponent}, b));
  ASSERT_THAT(ordered, Good());
  ASSERT_EQ(ordered.value().results().size(), 1u);
  EXPECT_THAT(ordered.value().results()[0], HasStatus(Status::BadDuplicateReferenceNotAllowed))
    << "a HasOrderedComponent beside a held HasComponent to the same target was accepted";

  auto organised = mSession->node_management().try_add_references_sync(
    AddReferencesBuilder().add_reference_async(a.get_node_id(), organizes, b));
  ASSERT_THAT(organised, Good());
  ASSERT_EQ(organised.value().results().size(), 1u);
  EXPECT_THAT(organised.value().results()[0], HasStatus(Status::Good));

  std::vector<std::string> expected{forward_ref(hasComponent, b), forward_ref(organizes, b)};
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(browse_forward(*mSession, a.get_node_id(), NodeId{ReferenceTypeId::HierarchicalReferences}, true),
    expected);
}

class DeleteReferencesIdentity : public ReferenceDuplicates
{};

// Part 3 section 4.3.4: "Any subtypes of concrete ReferenceTypes are considered to be equal to the base
// concrete ReferenceTypes when identifying References", so a DeleteReferences naming HasComponent to X names
// the held HasOrderedComponent to X (DL-11 as amended: a removal matches as an add does). The Nodes and
// References are added through AddNodes and AddReferences; the fixture's NodeManagementDelegate removes
// through the source Node, as the compliance server's does. The Organizes to Y is the control that only the
// Reference named is removed.
// @relation(AC-SVR-ADDRSP-260-REMOVAL-USES-IDENTITY, scope=function)
TEST_F(DeleteReferencesIdentity, ADeleteNamingHasComponentRemovesAHeldHasOrderedComponent)
{
  const NodeId a{mNamespaceIndex, uint32_t{9820}};
  const NodeId x{mNamespaceIndex, uint32_t{9821}};
  const NodeId y{mNamespaceIndex, uint32_t{9822}};
  const NodeId organizes{ReferenceTypeId::Organizes};
  {
    AddNodesRequest request;
    request.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DeleteIdentityA"}, a));
    request.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DeleteIdentityX"}, x));
    request.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DeleteIdentityY"}, y));
    auto added = mSession->node_management().try_add_nodes_sync(std::move(request));
    ASSERT_THAT(added, Good());
    ASSERT_EQ(added.value().results().size(), 3u);
    for (const auto& result : added.value().results())
      ASSERT_THAT(result, Good());
  }
  {
    auto added = mSession->node_management().try_add_references_sync(
      AddReferencesBuilder()
        .add_reference_async(a, NodeId{ReferenceTypeId::HasOrderedComponent}, x)
        .add_reference_async(a, organizes, y));
    ASSERT_THAT(added, Good());
    ASSERT_EQ(added.value().results().size(), 2u);
    ASSERT_THAT(added.value().results()[0], HasStatus(Status::Good));
    ASSERT_THAT(added.value().results()[1], HasStatus(Status::Good));
  }

  DeleteReferencesRequest request;
  DeleteReferencesItem item;
  item.source_node_id() = a;
  item.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
  item.is_forward() = true;
  item.target_node_id() = ExpandedNodeId{x};
  item.delete_bidirectional() = false;
  request.references_to_delete().push_back(std::move(item));
  auto deleted = mSession->node_management().try_delete_references_sync(std::move(request));
  ASSERT_THAT(deleted, Good());
  ASSERT_EQ(deleted.value().results().size(), 1u);
  EXPECT_THAT(deleted.value().results()[0], HasStatus(Status::Good));

  std::vector<std::string> expected{
    forward_ref(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType}),
    forward_ref(organizes, y)};
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(browse_forward(*mSession, a, NodeId{ReferenceTypeId::References}, true), expected)
    << "a DeleteReferences naming HasComponent to X did not remove the HasOrderedComponent to X alone";
}

// Part 3 section 4.3.4 holds in both directions: a DeleteReferences naming HasOrderedComponent to Z names the
// held HasComponent to Z. Organizes, a concrete type unrelated to HasComponent, is the control that a delete
// does not identify a Reference of an unrelated type; the Organizes to Y is held throughout.
// @relation(AC-SVR-ADDRSP-260-REMOVAL-USES-IDENTITY, scope=function)
TEST_F(DeleteReferencesIdentity, ADeleteNamingHasOrderedComponentRemovesAHeldHasComponent)
{
  const NodeId a{mNamespaceIndex, uint32_t{9823}};
  const NodeId z{mNamespaceIndex, uint32_t{9824}};
  const NodeId y{mNamespaceIndex, uint32_t{9825}};
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  const NodeId organizes{ReferenceTypeId::Organizes};
  const NodeId hasTypeDefinition{ReferenceTypeId::HasTypeDefinition};
  const NodeId baseObjectType{ObjectTypeId::BaseObjectType};
  {
    AddNodesRequest request;
    request.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DeleteIdentityA2"}, a));
    request.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DeleteIdentityZ"}, z));
    request.nodes_to_add().push_back(make_add_object(QualifiedName{mNamespaceIndex, "DeleteIdentityY2"}, y));
    auto added = mSession->node_management().try_add_nodes_sync(std::move(request));
    ASSERT_THAT(added, Good());
    ASSERT_EQ(added.value().results().size(), 3u);
    for (const auto& result : added.value().results())
      ASSERT_THAT(result, Good());
  }
  {
    auto added = mSession->node_management().try_add_references_sync(
      AddReferencesBuilder().add_reference_async(a, hasComponent, z).add_reference_async(a, organizes, y));
    ASSERT_THAT(added, Good());
    ASSERT_EQ(added.value().results().size(), 2u);
    ASSERT_THAT(added.value().results()[0], HasStatus(Status::Good));
    ASSERT_THAT(added.value().results()[1], HasStatus(Status::Good));
  }
  const auto deleteForward = [this, a, z](const NodeId& type)
  {
    DeleteReferencesRequest request;
    DeleteReferencesItem item;
    item.source_node_id() = a;
    item.reference_type_id() = type;
    item.is_forward() = true;
    item.target_node_id() = ExpandedNodeId{z};
    item.delete_bidirectional() = false;
    request.references_to_delete().push_back(std::move(item));
    return mSession->node_management().try_delete_references_sync(std::move(request));
  };

  const auto unrelated = deleteForward(organizes);
  ASSERT_THAT(unrelated, Good());
  ASSERT_EQ(unrelated.value().results().size(), 1u);
  std::vector<std::string> expected{
    forward_ref(hasTypeDefinition, baseObjectType), forward_ref(hasComponent, z), forward_ref(organizes, y)};
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(browse_forward(*mSession, a, NodeId{ReferenceTypeId::References}, true), expected)
    << "a DeleteReferences naming Organizes to Z removed a Reference of the unrelated type HasComponent";

  const auto subtype = deleteForward(NodeId{ReferenceTypeId::HasOrderedComponent});
  ASSERT_THAT(subtype, Good());
  ASSERT_EQ(subtype.value().results().size(), 1u);
  EXPECT_THAT(subtype.value().results()[0], HasStatus(Status::Good));
  expected = {forward_ref(hasTypeDefinition, baseObjectType), forward_ref(organizes, y)};
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(browse_forward(*mSession, a, NodeId{ReferenceTypeId::References}, true), expected)
    << "a DeleteReferences naming HasOrderedComponent to Z did not remove the HasComponent to Z alone";
}

// OPC 10000-4 5.7.5.1 (Table 31): deleteBidirectional FALSE deletes "only the specified Reference". The
// fixture's delegate removes through the source Node and passes the flag on as ReferenceHalves. Organizes,
// whose halves an add pairs, keeps the target's half; the TRUE case below is the control. Fails on the
// unchanged code, which removed both halves of Organizes whatever the flag.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-DELETE-BIDIRECTIONAL-FALSE-KEEPS-THE-TARGETS-HALF, scope=function)
TEST_F(DeleteReferencesIdentity, ADeleteWithDeleteBidirectionalFalseLeavesTheTargetsOrganizesHalf)
{
  const NodeId organizes{ReferenceTypeId::Organizes};
  auto a = make_object(9830, "HalvesFalseA");
  auto b = make_object(9831, "HalvesFalseB");
  ASSERT_TRUE(a.try_add_reference_sync(organizes, b.get_node_id()).is_good());
  ASSERT_EQ(browse_inverse(*mSession, b.get_node_id(), organizes, false),
    (std::vector<std::string>{forward_ref(organizes, a.get_node_id())}))
    << "the add did not store B's half";

  DeleteReferencesRequest request;
  DeleteReferencesItem item;
  item.source_node_id() = a.get_node_id();
  item.reference_type_id() = organizes;
  item.is_forward() = true;
  item.target_node_id() = ExpandedNodeId{b.get_node_id()};
  item.delete_bidirectional() = false;
  request.references_to_delete().push_back(std::move(item));
  auto deleted = mSession->node_management().try_delete_references_sync(std::move(request));
  ASSERT_THAT(deleted, Good());
  ASSERT_EQ(deleted.value().results().size(), 1u);
  EXPECT_THAT(deleted.value().results()[0], HasStatus(Status::Good));

  EXPECT_TRUE(browse_forward(*mSession, a.get_node_id(), organizes, false).empty())
    << "A kept the Reference the request named";
  EXPECT_EQ(browse_inverse(*mSession, b.get_node_id(), organizes, false),
    (std::vector<std::string>{forward_ref(organizes, a.get_node_id())}))
    << "deleteBidirectional FALSE removed the target's half too";
}

// OPC 10000-4 5.7.5.1 (Table 31): deleteBidirectional TRUE deletes the Reference in both directions, whatever
// its type. HasDictionaryEntry, whose halves an add does not pair, holds both halves here, stored one by one;
// the delete removes both. Fails on the unchanged code, which removed the target's half of a paired type
// only.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-06-DELETE-BIDIRECTIONAL-TRUE-REMOVES-BOTH-HALVES, scope=function)
TEST_F(DeleteReferencesIdentity, ADeleteWithDeleteBidirectionalTrueRemovesBothHalvesOfAnUnpairedType)
{
  const NodeId hasDictionaryEntry{ReferenceTypeId::HasDictionaryEntry};
  auto a = make_object(9832, "HalvesTrueA");
  auto b = make_object(9833, "HalvesTrueB");
  ASSERT_TRUE(a.try_add_reference_sync(hasDictionaryEntry, b.get_node_id()).is_good());
  ASSERT_TRUE(b.try_add_reference_sync(hasDictionaryEntry, ExpandedNodeId{a.get_node_id()}, false).is_good());
  ASSERT_EQ(browse_inverse(*mSession, b.get_node_id(), hasDictionaryEntry, false),
    (std::vector<std::string>{forward_ref(hasDictionaryEntry, a.get_node_id())}))
    << "B does not hold its half";

  DeleteReferencesRequest request;
  DeleteReferencesItem item;
  item.source_node_id() = a.get_node_id();
  item.reference_type_id() = hasDictionaryEntry;
  item.is_forward() = true;
  item.target_node_id() = ExpandedNodeId{b.get_node_id()};
  item.delete_bidirectional() = true;
  request.references_to_delete().push_back(std::move(item));
  auto deleted = mSession->node_management().try_delete_references_sync(std::move(request));
  ASSERT_THAT(deleted, Good());
  ASSERT_EQ(deleted.value().results().size(), 1u);
  EXPECT_THAT(deleted.value().results()[0], HasStatus(Status::Good));

  EXPECT_TRUE(browse_forward(*mSession, a.get_node_id(), hasDictionaryEntry, false).empty())
    << "A kept the Reference the request named";
  EXPECT_TRUE(browse_inverse(*mSession, b.get_node_id(), hasDictionaryEntry, false).empty())
    << "deleteBidirectional TRUE left the target's half of a HasDictionaryEntry";
}

class ImportReferences : public ComplianceNodeManagement
{
protected:
  /// A NodeSet in @p uri with Object A (ns=1;i=1), listed first, and Object B (ns=1;i=2), listed after it:
  /// A holds the forward half of one Reference to B typed @p forwardType, and B the inverse half typed
  /// @p inverseType.
  static std::string two_halves(string_view uri, string_view forwardType, string_view inverseType)
  {
    return fmt::format(R"xml(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>{0}</Uri>
  </NamespaceUris>
  <Models>
    <Model ModelUri="{0}" Version="1.0.0" PublicationDate="2026-01-01T00:00:00Z">
      <RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.05.03" PublicationDate="2023-12-15T00:00:00Z" />
    </Model>
  </Models>
  <UAObject NodeId="ns=1;i=1" BrowseName="1:HalvesA">
    <DisplayName>HalvesA</DisplayName>
    <References>
      <Reference ReferenceType="i=40">i=58</Reference>
      <Reference ReferenceType="i=35" IsForward="false">i=85</Reference>
      <Reference ReferenceType="{1}">ns=1;i=2</Reference>
    </References>
  </UAObject>
  <UAObject NodeId="ns=1;i=2" BrowseName="1:HalvesB">
    <DisplayName>HalvesB</DisplayName>
    <References>
      <Reference ReferenceType="i=40">i=58</Reference>
      <Reference ReferenceType="{2}" IsForward="false">ns=1;i=1</Reference>
    </References>
  </UAObject>
</UANodeSet>)xml",
      uri,
      forwardType,
      inverseType);
  }

  Result<NodeSetImportSummary> import(const std::string& xml)
  {
    NodeSetImportOptions options;
    // The imported namespace grants this fixture's Session what the fixture's own namespace does, so a Browse
    // can see its References.
    options.namespaceFactory = [executor = mServerThreadPool.executor()](
                                 string_view uri) -> shared_ptr<Namespace>
    {
      auto created = default_ns::Namespace::create(uri, executor);
      RolePermissionType permissions;
      permissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
      permissions.permissions() = all_node_management_permissions();
      created->set_namespace_defaults(std::vector<RolePermissionType>{permissions}, std::nullopt);
      return created;
    };
    const auto* bytes = reinterpret_cast<const std::byte*>(xml.data());
    memory_stream_device::ExternalReadOnly device{std::span<const std::byte>{bytes, xml.size()}};
    MemoryStream stream{device};
    return mServer->try_import_nodeset_sync(stream, std::move(options));
  }

  /// Every Reference A and B hold, for a failure message.
  std::string held_by(const NodeId& node)
  {
    std::string listed;
    auto found = mServer->address_space().try_find_node_sync(node);
    if (found.is_bad())
      return "(" + to_string(node) + " not found)";
    auto held = found.value().try_get_references_sync();
    if (held.is_bad())
      return "(references unreadable)";
    for (const auto& reference : held.value())
      listed += std::string{reference.is_forward() ? "" : "inverse "} + to_string(reference.type_id()) +
                " -> " + to_string(reference.target_id().node_id()) + "; ";
    return listed;
  }
};

// DL-11 as amended after the fourth review: the two halves of one Reference are the same Reference (Part 3
// section 4.3.4), so a file whose halves name a type and its subtype imports with the subtype, whichever half
// the engine meets first, and a file whose halves name two sibling types fails with the refusal and the XML
// location rather than skipping a Reference and reporting success. The engine meets the halves in the order
// of an unordered map (NodeSet::nodes()), so the first two files, which differ only in which half names the
// subtype, stand for either order. HasOrderedComponent (i=49) and HasAddIn (i=17604) are both direct subtypes
// of the concrete HasComponent (i=47), Part 5 sections 11.8 and 11.21, and neither is a subtype of the other.
// Each file is imported into a namespace of its own, which stands in for a fresh server: an import adds its
// namespace and touches no other.
// @relation(AC-SVR-ADDRSP-260-IMPORT-DISAGREEING-HALVES-FAIL, scope=function)
TEST_F(ImportReferences, HalvesThatDisagreeOnTheTypeFailTheImport)
{
  const NodeId hasComponent{ReferenceTypeId::HasComponent};
  const NodeId hasOrderedComponent{ReferenceTypeId::HasOrderedComponent};
  const auto index = [this](const std::string& uri)
  {
    return mServer->address_space().namespace_array().get_namespace_index(uri);
  };
  const auto expectTheSubtypeOnce =
    [&](const std::string& uri, string_view forwardType, string_view inverseType)
  {
    const auto imported = import(two_halves(uri, forwardType, inverseType));
    ASSERT_TRUE(imported.is_good()) << uri << " answered " << to_string(imported.status_code());
    const NodeId a{index(uri), uint32_t{1}};
    const NodeId b{index(uri), uint32_t{2}};
    EXPECT_EQ(browse_forward(*mSession, a, hasComponent, true),
      (std::vector<std::string>{forward_ref(hasOrderedComponent, b)}))
      << uri << ": A holds " << held_by(a);
    EXPECT_EQ(browse_inverse(*mSession, b, hasComponent, true),
      (std::vector<std::string>{forward_ref(hasOrderedComponent, a)}))
      << uri << ": B holds " << held_by(b);
  };
  expectTheSubtypeOnce("urn:test:import-halves-component-on-a", "i=47", "i=49");
  expectTheSubtypeOnce("urn:test:import-halves-ordered-on-a", "i=49", "i=47");

  const std::string siblingsUri{"urn:test:import-halves-siblings"};
  const auto siblings = import(two_halves(siblingsUri, "i=49", "i=17604"));
  const auto describe = [&]
  {
    if (siblings.is_bad())
      return to_string(siblings.status_code());
    return "Good; A holds " + held_by(NodeId{index(siblingsUri), uint32_t{1}}) + "B holds " +
           held_by(NodeId{index(siblingsUri), uint32_t{2}});
  };
  EXPECT_EQ(siblings.status_code().as_status(), Status::BadDuplicateReferenceNotAllowed)
    << "halves typed HasOrderedComponent and HasAddIn: " << describe();
  EXPECT_TRUE(detail_chain_has_code(siblings.status_code(), "DuplicateReferenceOfAnotherType")) << describe();
  EXPECT_TRUE(detail_chain_has_context(siblings.status_code(), ContextKeys::sourceLocation.value()))
    << "the refusal does not carry the XML location: " << describe();
}

// A guard: a file listing both halves of one Reference imports with each half stored once. Once the namespace
// refuses a held Reference, a half the import meets twice must count as present, not fail the import.
// @relation(AC-SVR-ADDRSP-260-IMPORT-STORES-BOTH-HALVES-ONCE, scope=function)
TEST_F(ImportReferences, AFileListingBothHalvesStoresEachOnce)
{
  const auto imported = import(two_halves("urn:test:import-halves-agree", "i=35", "i=35"));
  ASSERT_TRUE(imported.is_good()) << to_string(imported.status_code());
  const uint16_t index =
    mServer->address_space().namespace_array().get_namespace_index("urn:test:import-halves-agree");
  const NodeId a{index, uint32_t{1}};
  const NodeId b{index, uint32_t{2}};
  const NodeId organizes{ReferenceTypeId::Organizes};

  EXPECT_EQ(
    browse_forward(*mSession, a, organizes, false), (std::vector<std::string>{forward_ref(organizes, b)}))
    << "A holds " << held_by(a);
  auto inverse = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                    .browse(b)
                                                    .direction(BrowseDirection::Inverse)
                                                    .reference_type(organizes)
                                                    .include_subtypes(false));
  ASSERT_THAT(inverse, Good());
  ASSERT_EQ(inverse.value().results().size(), 1u);
  EXPECT_EQ(inverse.value().results().payload()[0].references().size(), 1u) << "B holds " << held_by(b);
}

// DeleteNodes' deleteTargetReferences reaches the address space (DL-124 (4)): FALSE deletes the Node and the
// References it holds, and leaves the half the Node R holds of its Organizes Reference to it (OPC 10000-4
// 5.7.4.2, Table 28: "delete only the References for which the Node to delete is the source"); TRUE, the
// control, removes R's half too ("delete References in TargetNodes that Reference the Node to delete"). The
// fixture's delegate passes the flag through as the deletion's ReferenceHalves; before DL-124 (4) the flag
// removed R's half either way.
// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-08-DELETE-TARGET-REFERENCES-FALSE-LEAVES-THE-REFERRERS-HALF, scope=function)
TEST_F(ComplianceNodeManagement, DeleteTargetReferencesFalseLeavesTheReferrersHalfAndTrueRemovesIt)
{
  auto addressSpace = mServer->address_space();
  const auto referrerHolds = [&addressSpace](const NodeId& referrer, const NodeId& deleted)
  {
    auto references = addressSpace.find_node_sync(referrer).try_get_references_sync();
    EXPECT_TRUE(references.is_good()) << to_string(references.status_code());
    if (!references.is_good())
      return false;
    for (const auto& reference : references.value())
    {
      if (reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::Organizes} &&
          reference.target_id() == ExpandedNodeId{deleted})
        return true;
    }
    return false;
  };

  for (const bool deleteTargetReferences : {false, true})
  {
    SCOPED_TRACE(deleteTargetReferences ? "deleteTargetReferences TRUE" : "deleteTargetReferences FALSE");
    const uint32_t base = deleteTargetReferences ? 9782u : 9780u;
    const NodeId target{mNamespaceIndex, base};
    const NodeId referrer{mNamespaceIndex, base + 1u};
    for (const auto& nodeId : {target, referrer})
    {
      auto created = addressSpace.try_create_node_sync(nodeId, NodeClass::Object, {});
      ASSERT_TRUE(created.is_good()) << to_string(created.status_code());
    }
    ASSERT_TRUE(addressSpace.find_node_sync(referrer)
                  .try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, target)
                  .is_good());
    ASSERT_TRUE(referrerHolds(referrer, target)) << "the referrer must hold its half, or this proves nothing";

    auto result =
      mSession->node_management().try_delete_nodes_sync(delete_nodes({target}, deleteTargetReferences));
    ASSERT_THAT(result, Good());
    auto response = std::move(result).value();
    ASSERT_EQ(response.results().size(), 1u);
    EXPECT_THAT(response.results()[0], Good());
    EXPECT_TRUE(addressSpace.try_find_node_sync(target).is_bad()) << "the Node was not deleted";

    EXPECT_EQ(referrerHolds(referrer, target), !deleteTargetReferences)
      << (deleteTargetReferences
             ? "TRUE shall remove the References other Nodes hold to the deleted Node"
             : "FALSE shall delete only the References the deleted Node is the source of");
  }
}
