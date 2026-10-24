// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef COMPLIANCE_HELPERS_H
#define COMPLIANCE_HELPERS_H

#include <gtest/gtest.h>

#include "helpers/sanitizer_budget.h"

#include "ua_test_server.h"

#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_attribute_write_mask.h"
#include "ua_address_space.h"
#include "ua_role_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_certificate_store_files.h"
#include "ua_client.h"
#include "ua_core_client.h"
#include "ua_client_test_hooks.h"
#include "test_log_sink.h"
#include "ua_crypto.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_default_method_node.h"
#include "ua_default_variable_node.h"
#include "ua_timer.h"
#include "ua_method_adapter.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_range.h"
#include "ua_variabletype_id.h"
#include "ua_referencetype_id.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_security_policy.h"
#include "ua_transport_connection.h"
#include "ua_value_rank.h"

#include "fuzz_security_policy.h"
#include "fuzz_transport_connection.h"
#include "mutable_claim_authenticator.h"

#include "access_control_test_support.h"
#include "test_utilities.h"

#include <filesystem>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// A log sink that captures records for assertions AND forwards to the buffering test_log_sink() so
// output still appears on failure. Installed at construction on fixtures that assert on server logs
// (there is no runtime sink setter). Level checks use `<=` because lower LogLevel = higher severity.
namespace ua::test_utils
{

/// A client's patience for a response, widened for an instrumented build.
///
/// The service timeout is a property of the BUILD, not of the behaviour under test. A sanitized
/// build runs roughly an order of magnitude slower, so the 10s default turns "the server answered"
/// into BadTimeout on work that is merely slow - a multi-chunk Read over an 8 KiB buffer, an
/// ActivateSession carrying issued-token ECC. Applied to every client this header builds, rather
/// than in each fixture that trips over it. Nothing is weakened: a server that never answers still
/// times out, and every assertion still has to hold.
inline ua::client::CreateConfig scale_service_timeout(ua::client::CreateConfig cfg)
{
  cfg.client.defaultServiceTimeout = scaled(cfg.client.defaultServiceTimeout);
  return cfg;
}

}  // namespace ua::test_utils

class CapturingLogSink : public ua::LogSink
{
public:
  void log(const ua::LogEntry& entry) override
  {
    test_log_sink()->log(entry);
    std::lock_guard lock(mMutex);
    mEntries.push_back({entry.level, std::string(entry.category), entry.message});
  }

  struct Entry
  {
    ua::LogLevel level;
    std::string category;
    std::string message;
  };

  bool has_warning_or_error() const
  {
    std::lock_guard lock(mMutex);
    for (const auto& e : mEntries)
    {
      if (e.level >= ua::LogLevel::Warning)  // ua::LogLevel ascends Trace..Critical
        return true;
    }
    return false;
  }

  std::vector<Entry> records() const
  {
    std::lock_guard lock(mMutex);
    return mEntries;
  }

  void clear()
  {
    std::lock_guard lock(mMutex);
    mEntries.clear();
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

// ---------------------------------------------------------------------------
// ComplianceBase: server + client, no session
// ---------------------------------------------------------------------------

/// Grants a fixture's own namespaces to the Roles its test client holds.
///
/// Once the Role model is engaged, a namespace that has declared no permissions publishes an EMPTY
/// default and hides every undecorated node it owns. Nodes a fixture creates - including the ones the
/// server allocates on its behalf, such as Conditions under ObjectsFolder - land in such namespaces, so
/// without this every read, browse and history call against them is refused Bad_UserAccessDenied.
///
/// The unconfigured state is an ENGAGED, EMPTY array, not an absent one, so "has the namespace spoken
/// for itself?" is `!empty()` and not `has_value()`. A namespace that has granted something keeps its
/// own answer, which is what leaves a fixture that deliberately narrows access alone.
inline void grant_fixture_namespace_permissions(ua::AddressSpace addressSpace)
{
  RolePermissionType anonymous;
  anonymous.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
  anonymous.permissions() = ua::test_helpers::all_permissions();
  RolePermissionType securityAdmin;
  securityAdmin.role_id() = NodeId{ObjectId::WellKnownRole_SecurityAdmin};
  securityAdmin.permissions() = ua::test_helpers::all_permissions();
  const std::vector<RolePermissionType> grants{anonymous, securityAdmin};

  const auto count = addressSpace.namespace_array().get_namespace_array().size();
  for (uint16_t index = 0; index < count; ++index)
  {
    auto owned =
      std::dynamic_pointer_cast<default_ns::Namespace>(addressSpace.namespace_array().get_namespace(index));
    if (!owned)
      continue;
    const auto declared = owned->default_role_permissions();
    if (declared && !declared->empty())
      continue;
    owned->set_namespace_defaults(grants, std::nullopt);
  }
}

class ComplianceBase : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mServer.create([this](ua::ApplicationConfig& cfg) { configure_application_config(cfg); },
      [this](ua::server::ServerConfig& cfg) { configure_server_config(cfg); },
      /*logSink=*/nullptr,
      ua::LogLevel::Debug,
      [this](ua::ApplicationIdentity& identity) { configure_application_identity(identity); });
    configure_server();
    grant_fixture_namespace_permissions(mServer.server().address_space());

    ServerEndpointConfig endpoint;
    endpoint.name = "None";
    endpoint.messageSecurityMode = MessageSecurityMode::None;
    endpoint.securityPolicyId = SecurityPolicyId::None;
    endpoint.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));

    mListener = mServer.listen_ephemeral();
    mServer.add_endpoint(mListener, endpoint);
    mServer.start();

    auto urls = mServer.server().advertised_urls(mListener);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    // The server's log sink is installed by TestServer::create (test_log_sink()); the client gets it
    // at construction here.
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      ua::test_utils::scale_service_timeout(
        ua::client::CreateConfig{.identity = ua::ApplicationIdentity::load_default(),
          .application = ua::test_utils::create_test_config()}),
      ua::client::ClientComponents{
        .crypto = ua::test_helpers::test_crypto(), .logSink = test_log_sink(), .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    // Drop the client handle BEFORE stopping the pool so that any impl-owned
    // strand-bound resources (channels, sessions, reverse-connect listeners) get
    // torn down while the pool can still process their teardown posts. Stopping
    // the pool first leaves outstanding handlers that the watchdog has to abort.
    mClient.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
  }

  virtual void configure_server()
  {}

  // Creation-time server-config hook (applied before the server is built, unlike
  // configure_server() which runs after). Override to adjust ServerConfig
  // fields that are immutable post-construction (e.g. connection throttling).
  virtual void configure_server_config(ua::server::ServerConfig& cfg)
  {
    // Declare the base server facet.
    //
    // `serverProfiles` has no default anywhere in the SDK -- it is only ever populated from a
    // configuration file -- so a server built through the programmatic API publishes an EMPTY
    // ServerProfileArray. Part 5 section 6.3.2 requires that array to list the facets the server
    // implements, and `AC-SVR-BASE-028` makes the declaration the thing a client checks the
    // address space against, so a server declaring nothing is not conforming.
    // `D-NO-DEFAULT-SERVER-PROFILE` records the SDK-side gap; this makes the compliance fixture a
    // conforming server so that tests asserting over it are asserting over something meaningful.
    if (cfg.server_capabilities().serverProfiles.empty())
    {
      cfg.server_capabilities().serverProfiles.emplace_back(
        "http://opcfoundation.org/UA-Profile/Server/StandardUA2017");
    }
  }

  // Creation-time APPLICATION-config hook, applied before configure_server_config. Override to adjust
  // ApplicationConfig fields that are immutable post-construction - the default locale, the
  // application description, stack limits. Without this the shared fixtures could only reach
  // ServerConfig, which left every ApplicationConfig field untestable through them.
  virtual void configure_application_config(ua::ApplicationConfig&)
  {}

  // Creation-time APPLICATION-IDENTITY hook. BuildInfo, product URI and application name are immutable
  // once the server exists and are reachable no other way, so any row covering them needs this.
  virtual void configure_application_identity(ua::ApplicationIdentity&)
  {}

  TestServer mServer;
  boost::asio::thread_pool mClientThreadPool;
  ListenerHandle mListener{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
};

// ---------------------------------------------------------------------------
// ComplianceWithSession: channel + session opened
// ---------------------------------------------------------------------------
class ComplianceWithSession : public ComplianceBase
{
protected:
  void SetUp() override
  {
    ComplianceBase::SetUp();
    mChannel.emplace(mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl}));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceTest"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceBase::TearDown();
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// ---------------------------------------------------------------------------
// ComplianceWithNodes: session + test nodes in a custom namespace
// ---------------------------------------------------------------------------
class ComplianceWithNodes : public ComplianceWithSession
{
protected:
  virtual std::vector<RolePermissionType> test_namespace_role_permissions() const
  {
    RolePermissionType anonymousPermissions;
    anonymousPermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymousPermissions.permissions() = ua::test_helpers::all_permissions();
    return {std::move(anonymousPermissions)};
  }

  virtual std::optional<AccessRestrictionType> test_namespace_access_restrictions() const
  {
    return std::nullopt;
  }

  void configure_server() override
  {
    auto addressSpace = mServer.server().address_space();
    mTestNamespace = default_ns::Namespace::create("urn:test:compliance", mServer.thread_pool().executor());
    mTestNamespaceIndex = addressSpace.add_namespace_sync(mTestNamespace);
    mTestNamespace->set_namespace_defaults(
      test_namespace_role_permissions(), test_namespace_access_restrictions());

    // Writable Variable: ns=mTestNamespaceIndex;i=1000
    mWritableVariableId = NodeId{mTestNamespaceIndex, uint32_t{1000}};
    auto varNode = addressSpace.create_node_sync(mWritableVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    varNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto variable = varNode.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNamespaceIndex, "WritableInt32"});
    variable->set_display_name(LocalizedText{"", "WritableInt32"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{42});
    // TimestampWrite: tests write SourceTimestamps to it, which Part 3 section 8.57 allows only with it.
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::CurrentWrite,
      AccessLevelType::Bit::TimestampWrite});

    // Part 3 section 5.6.4: a DataVariable shall be the TargetNode of at least one HasComponent Reference
    // from an Object, ObjectType, DataVariable or VariableType. Every DataVariable below was hung off
    // ObjectsFolder by Organizes alone, which is exactly what the clause forbids -- Organizes
    // licenses an ADDITIONAL Reference, it does not stand in for the mandatory one. Both halves are
    // added because the Node primitive is one-sided (`add_reference_sync` writes the Reference on the
    // node it is called on only) and Browse answers an inverse request from the browsed node's own
    // Reference list, so without the second call an inverse Browse of the Variable finds no owner.
    // The Organizes edge is REPLACED rather than kept: keeping both would return each Variable twice
    // from a hierarchical Browse of ObjectsFolder.
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mWritableVariableId);
    varNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // Full-access Variable: ns=mTestNamespaceIndex;i=1001
    // Has all access level bits including StatusWrite and TimestampWrite.
    mFullAccessVariableId = NodeId{mTestNamespaceIndex, uint32_t{1001}};
    auto fullVarNode = addressSpace.create_node_sync(mFullAccessVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    fullVarNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto fullVariable = fullVarNode.as<VariableAccessor>();
    ASSERT_TRUE(fullVariable.has_value());
    fullVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "FullAccessInt32"});
    fullVariable->set_display_name(LocalizedText{"", "FullAccessInt32"});
    fullVariable->set_data_type(NodeId{DataTypeId::Int32});
    fullVariable->write_value_sync(int32_t{0});
    fullVariable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::CurrentWrite,
      AccessLevelType::Bit::StatusWrite,
      AccessLevelType::Bit::TimestampWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mFullAccessVariableId);
    fullVarNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // Folder Object: ns=mTestNamespaceIndex;i=2000
    mTestFolderId = NodeId{mTestNamespaceIndex, uint32_t{2000}};
    auto folderNode = addressSpace.create_node_sync(mTestFolderId, NodeClass::Object);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    folderNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto folder = folderNode.as<ObjectAccessor>();
    ASSERT_TRUE(folder.has_value());
    folder->set_browse_name(QualifiedName{mTestNamespaceIndex, "TestFolder"});
    folder->set_display_name(LocalizedText{"", "TestFolder"});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mTestFolderId);
    // Bidirectional: add inverse Organizes reference on TestFolder pointing back to ObjectsFolder.
    folderNode.add_reference_sync(
      NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}}, false);

    // Method with handler (Add): ns=mTestNamespaceIndex;i=3000 (on TestFolder)
    // Takes 2 Int32 inputs, returns 1 Int32 output (sum).
    mTestMethodId = NodeId{mTestNamespaceIndex, uint32_t{3000}};
    auto methodNode = addressSpace.create_node_sync(mTestMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    ASSERT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{mTestNamespaceIndex, "TestMethod"});
    method->set_display_name(LocalizedText{"", "TestMethod"});
    method->set_executable(true);
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mTestMethodId);
    // Part 3 (Methods): a Method is the TargetNode of at least one HasComponent Reference. The Node
    // primitive is one-sided, so the inverse half has to be added on the Method itself or an inverse
    // Browse of it finds no owner.
    methodNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, /*isForward=*/false);

    // Install Add handler via MethodAdapter<std::tuple<int32_t, int32_t>>
    {
      using AddArgs = std::tuple<int32_t, int32_t>;
      auto addHandler = [](const NodeId& /*objectId*/,
                          const AddArgs& inputArgs,
                          std::shared_ptr<const MethodCallContext> /*context*/,
                          CallMethodResult result,
                          CallMethodCompleteCallback callback)
      {
        auto [a, b] = inputArgs;
        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{static_cast<int32_t>(a + b)};
        callback(CallResult{std::move(result)});
      };

      auto* callSource = mTestNamespace->find_node<Node>(mTestMethodId)->method_call_source();
      ASSERT_NE(callSource, nullptr);
      callSource->set_call_handler(MethodAdapter<AddArgs>{addHandler});
    }

    // Non-executable method: ns=mTestNamespaceIndex;i=3001 (on TestFolder)
    mNonExecutableMethodId = NodeId{mTestNamespaceIndex, uint32_t{3001}};
    auto neMethodNode = addressSpace.create_node_sync(mNonExecutableMethodId, NodeClass::Method);
    auto neMethod = neMethodNode.as<MethodAccessor>();
    ASSERT_TRUE(neMethod.has_value());
    neMethod->set_browse_name(QualifiedName{mTestNamespaceIndex, "NonExecutableMethod"});
    neMethod->set_display_name(LocalizedText{"", "NonExecutableMethod"});
    neMethod->set_executable(false);
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mNonExecutableMethodId);
    neMethodNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, /*isForward=*/false);
    // Install a handler anyway - the server should reject based on Executable attribute.
    {
      auto* callSource = mTestNamespace->find_node<Node>(mNonExecutableMethodId)->method_call_source();
      ASSERT_NE(callSource, nullptr);
      callSource->set_call_handler(
        [](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            cb)
        {
          CallMethodResult r;
          cb(CallResult{std::move(r)});
        });
    }

    // No-handler method: ns=mTestNamespaceIndex;i=3002 (on TestFolder)
    // Has no handler registered - calling should return BadNotSupported.
    mNoHandlerMethodId = NodeId{mTestNamespaceIndex, uint32_t{3002}};
    auto nhMethodNode = addressSpace.create_node_sync(mNoHandlerMethodId, NodeClass::Method);
    auto nhMethod = nhMethodNode.as<MethodAccessor>();
    ASSERT_TRUE(nhMethod.has_value());
    nhMethod->set_browse_name(QualifiedName{mTestNamespaceIndex, "NoHandlerMethod"});
    nhMethod->set_display_name(LocalizedText{"", "NoHandlerMethod"});
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mNoHandlerMethodId);
    nhMethodNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, /*isForward=*/false);

    // No-args method: ns=mTestNamespaceIndex;i=3003 (on TestFolder)
    // Takes no arguments, returns nothing - just succeeds.
    mNoArgsMethodId = NodeId{mTestNamespaceIndex, uint32_t{3003}};
    auto naMethodNode = addressSpace.create_node_sync(mNoArgsMethodId, NodeClass::Method);
    auto naMethod = naMethodNode.as<MethodAccessor>();
    ASSERT_TRUE(naMethod.has_value());
    naMethod->set_browse_name(QualifiedName{mTestNamespaceIndex, "NoArgsMethod"});
    naMethod->set_display_name(LocalizedText{"", "NoArgsMethod"});
    naMethod->set_executable(true);
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mNoArgsMethodId);
    naMethodNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, /*isForward=*/false);
    {
      auto* callSource = mTestNamespace->find_node<Node>(mNoArgsMethodId)->method_call_source();
      ASSERT_NE(callSource, nullptr);
      callSource->set_call_handler(
        [](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            cb)
        {
          CallMethodResult r;
          cb(CallResult{std::move(r)});
        });
    }

    // Encryption-required method: ns=mTestNamespaceIndex;i=3004 (on TestFolder)
    // Has AccessRestrictions.EncryptionRequired set.
    mEncryptionRequiredMethodId = NodeId{mTestNamespaceIndex, uint32_t{3004}};
    auto erMethodNode = addressSpace.create_node_sync(mEncryptionRequiredMethodId, NodeClass::Method);
    auto erMethodAcc = erMethodNode.as<MethodAccessor>();
    ASSERT_TRUE(erMethodAcc.has_value());
    erMethodAcc->set_browse_name(QualifiedName{mTestNamespaceIndex, "EncryptionRequiredMethod"});
    erMethodAcc->set_display_name(LocalizedText{"", "EncryptionRequiredMethod"});
    erMethodAcc->set_executable(true);
    erMethodNode.set_access_restrictions(
      AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mEncryptionRequiredMethodId);
    erMethodNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, /*isForward=*/false);
    {
      auto* callSource = mTestNamespace->find_node<Node>(mEncryptionRequiredMethodId)->method_call_source();
      ASSERT_NE(callSource, nullptr);
      callSource->set_call_handler(
        [](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            cb)
        {
          CallMethodResult r;
          cb(CallResult{std::move(r)});
        });
    }

    // Second test object: ns=mTestNamespaceIndex;i=2001 (sibling of TestFolder)
    // Used for BadMethodInvalid tests - the test methods are NOT components of this object.
    mOtherObjectId = NodeId{mTestNamespaceIndex, uint32_t{2001}};
    auto otherObjNode = addressSpace.create_node_sync(mOtherObjectId, NodeClass::Object);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    otherObjNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto otherObj = otherObjNode.as<ObjectAccessor>();
    ASSERT_TRUE(otherObj.has_value());
    otherObj->set_browse_name(QualifiedName{mTestNamespaceIndex, "OtherObject"});
    otherObj->set_display_name(LocalizedText{"", "OtherObject"});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mOtherObjectId);

    // An AssociatedWith pair: ns=mTestNamespaceIndex;i=2002 -AssociatedWith-> i=2001.
    //
    // Part 5 section 8.4 restricts AssociatedWith to relating two Objects, and
    // `EverySampledAssociatedWithConnectsTwoObjects` verifies that. Nothing else in this model
    // sources one, so without this pair that test would have no subject and its assertion would be vacuously
    // true -- and a criterion discharged by a skip is a green tick over an obligation nothing
    // exercises. Both ends are Objects, so a conforming server passes; a server that materialised
    // an AssociatedWith from or to a non-Object would be caught by the same walk.
    const NodeId associatedSourceId{mTestNamespaceIndex, uint32_t{2002}};
    auto associatedSourceNode = addressSpace.create_node_sync(associatedSourceId, NodeClass::Object);
    associatedSourceNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto associatedSource = associatedSourceNode.as<ObjectAccessor>();
    ASSERT_TRUE(associatedSource.has_value());
    associatedSource->set_browse_name(QualifiedName{mTestNamespaceIndex, "AssociatedSource"});
    associatedSource->set_display_name(LocalizedText{"", "AssociatedSource"});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, associatedSourceId);
    associatedSourceNode.add_reference_sync(NodeId{ReferenceTypeId::AssociatedWith}, mOtherObjectId);

    // A HasStructuredComponent exposure: ns=mTestNamespaceIndex;i=2003 "StructuredRange", a scalar
    // Variable of the Structure DataType Range (i=884, fields "Low" and "High", both Double), with
    // both fields exposed as DataVariables over HasStructuredComponent.
    //
    // Part 3 section 7.22.1 states every rule it has about that ReferenceType, and neither NS0 nor this
    // fixture sourced one -- NS0 links a complex DataVariable's sub-Variables with plain
    // HasComponent, which section 4.4.3 governs and which carries no naming rule. Without this pair
    // AC-SVR-ADDRSP-179/180/181/182 have no subject at all and their tests fail on their own
    // non-vacuity guards. The BrowseNames are the field names in namespace 0 -- the namespace of
    // Range, the Structure that first defines them, not the Variable's own -- and the DataType and
    // ValueRank are the field's, so a conforming server passes; a server that rewrote a BrowseName,
    // reparented it into the Variable's namespace, or altered the served DataType/ValueRank on the
    // way out is caught by the same walk.
    const NodeId structuredRangeId{mTestNamespaceIndex, uint32_t{2003}};
    auto structuredRangeNode = addressSpace.create_node_sync(structuredRangeId, NodeClass::Variable);
    structuredRangeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto structuredRange = structuredRangeNode.as<VariableAccessor>();
    ASSERT_TRUE(structuredRange.has_value());
    structuredRange->set_browse_name(QualifiedName{mTestNamespaceIndex, "StructuredRange"});
    structuredRange->set_display_name(LocalizedText{"", "StructuredRange"});
    structuredRange->set_data_type(NodeId{DataTypeId::Range});
    structuredRange->set_value_rank(ValueRank{ValueRank::scalar});
    Range structuredRangeValue;
    structuredRangeValue.low() = 0.0;
    structuredRangeValue.high() = 100.0;
    structuredRange->write_value_sync(Variant{structuredRangeValue});
    structuredRange->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, structuredRangeId);
    structuredRangeNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    const std::pair<uint32_t, const char*> rangeFields[]{{2004U, "Low"}, {2005U, "High"}};
    for (const auto& [fieldNumericId, fieldName] : rangeFields)
    {
      const NodeId fieldId{mTestNamespaceIndex, fieldNumericId};
      auto fieldNode = addressSpace.create_node_sync(fieldId, NodeClass::Variable);
      fieldNode.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
      auto fieldVariable = fieldNode.as<VariableAccessor>();
      ASSERT_TRUE(fieldVariable.has_value());
      // section 7.22.1: the BrowseName's NamespaceIndex is Range's (0), NOT the owning Variable's.
      fieldVariable->set_browse_name(QualifiedName{uint16_t{0}, fieldName});
      fieldVariable->set_display_name(LocalizedText{"", fieldName});
      fieldVariable->set_data_type(NodeId{DataTypeId::Double});
      fieldVariable->set_value_rank(ValueRank{ValueRank::scalar});
      fieldVariable->write_value_sync(double{0.0});
      fieldVariable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
      structuredRangeNode.add_reference_sync(NodeId{ReferenceTypeId::HasStructuredComponent}, fieldId);
      fieldNode.add_reference_sync(NodeId{ReferenceTypeId::HasStructuredComponent},
        ExpandedNodeId{structuredRangeId},
        /*isForward=*/false);
    }

    // Custom ObjectType with a method: ns=mTestNamespaceIndex;i=7000
    // Used for SVR-METH-CALL-011 (ObjectType HasComponent to Method) and
    // SVR-METH-CALL-012 (Object's ObjectType has HasComponent to Method).
    mTestObjectTypeId = NodeId{mTestNamespaceIndex, uint32_t{7000}};
    auto objTypeNode = addressSpace.create_node_sync(mTestObjectTypeId, NodeClass::ObjectType);
    auto objType = objTypeNode.as<ObjectTypeAccessor>();
    ASSERT_TRUE(objType.has_value());
    objType->set_browse_name(QualifiedName{mTestNamespaceIndex, "TestObjectType"});
    objType->set_display_name(LocalizedText{"", "TestObjectType"});
    // Part 5 section 6.2: every ObjectType shall directly or indirectly inherit from BaseObjectType. The
    // inverse HasSubtype leg is the whole of what a client can rely on -- the downward References
    // from BaseObjectType are explicitly not required -- so it is written on the type itself, the
    // same way compliance_method_tests.cpp roots SubTestObjectType.
    objTypeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasSubtype}, NodeId{ObjectTypeId::BaseObjectType}, /*isForward=*/false);

    // Method on the ObjectType: ns=mTestNamespaceIndex;i=7001
    mObjectTypeMethodId = NodeId{mTestNamespaceIndex, uint32_t{7001}};
    auto otMethodNode = addressSpace.create_node_sync(mObjectTypeMethodId, NodeClass::Method);
    auto otMethod = otMethodNode.as<MethodAccessor>();
    ASSERT_TRUE(otMethod.has_value());
    otMethod->set_browse_name(QualifiedName{mTestNamespaceIndex, "ObjectTypeMethod"});
    otMethod->set_display_name(LocalizedText{"", "ObjectTypeMethod"});
    otMethod->set_executable(true);
    objTypeNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mObjectTypeMethodId);
    otMethodNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestObjectTypeId}, /*isForward=*/false);
    {
      auto* callSource = mTestNamespace->find_node<Node>(mObjectTypeMethodId)->method_call_source();
      ASSERT_NE(callSource, nullptr);
      callSource->set_call_handler(
        [](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            cb)
        {
          CallMethodResult r;
          cb(CallResult{std::move(r)});
        });
    }

    // Object that is an instance of TestObjectType: ns=mTestNamespaceIndex;i=7002
    // Has HasTypeDefinition -> TestObjectType. Does NOT have direct HasComponent to the method.
    // Used for SVR-METH-CALL-012 (method resolved via ObjectType).
    mTypedObjectId = NodeId{mTestNamespaceIndex, uint32_t{7002}};
    auto typedObjNode = addressSpace.create_node_sync(mTypedObjectId, NodeClass::Object);
    auto typedObj = typedObjNode.as<ObjectAccessor>();
    ASSERT_TRUE(typedObj.has_value());
    typedObj->set_browse_name(QualifiedName{mTestNamespaceIndex, "TypedObject"});
    typedObj->set_display_name(LocalizedText{"", "TypedObject"});
    typedObjNode.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, mTestObjectTypeId);
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mTypedObjectId);

    // Object with writable DisplayName: ns=mTestNamespaceIndex;i=1002
    mWritableDisplayNameNodeId = NodeId{mTestNamespaceIndex, uint32_t{1002}};
    auto wdnNode = addressSpace.create_node_sync(mWritableDisplayNameNodeId, NodeClass::Object);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    wdnNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto wdnObject = wdnNode.as<ObjectAccessor>();
    ASSERT_TRUE(wdnObject.has_value());
    wdnObject->set_browse_name(QualifiedName{mTestNamespaceIndex, "WritableDisplayName"});
    wdnObject->set_display_name(LocalizedText{"en", "OriginalDisplay"});
    wdnObject->set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mWritableDisplayNameNodeId);

    // Encryption-required Variable: ns=mTestNamespaceIndex;i=1003
    // Has AccessRestrictions.EncryptionRequired - reading on None channel should fail.
    mEncryptionRequiredVariableId = NodeId{mTestNamespaceIndex, uint32_t{1003}};
    auto erNode = addressSpace.create_node_sync(mEncryptionRequiredVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    erNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto erVariable = erNode.as<VariableAccessor>();
    ASSERT_TRUE(erVariable.has_value());
    erVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "EncryptionRequired"});
    erVariable->set_display_name(LocalizedText{"", "EncryptionRequired"});
    erVariable->set_data_type(NodeId{DataTypeId::Int32});
    erVariable->write_value_sync(int32_t{99});
    erVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    erNode.set_access_restrictions(AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mEncryptionRequiredVariableId);
    erNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // Enum Variable (ServerState): ns=mTestNamespaceIndex;i=1004
    // DataType is ServerState (enum, values 0-7). Used for BadOutOfRange testing.
    mEnumVariableId = NodeId{mTestNamespaceIndex, uint32_t{1004}};
    auto enumNode = addressSpace.create_node_sync(mEnumVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    enumNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto enumVariable = enumNode.as<VariableAccessor>();
    ASSERT_TRUE(enumVariable.has_value());
    enumVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "EnumVariable"});
    enumVariable->set_display_name(LocalizedText{"", "EnumVariable"});
    enumVariable->set_data_type(NodeId{DataTypeId::ServerState});
    enumVariable->write_value_sync(int32_t{0});  // Running
    enumVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mEnumVariableId);
    enumNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // Byte array Variable: ns=mTestNamespaceIndex;i=1005
    // Used for ByteString-accepted-as-Byte-array testing (SVR-ATTR-WRITE-011).
    mByteArrayVariableId = NodeId{mTestNamespaceIndex, uint32_t{1005}};
    auto byteArrNode = addressSpace.create_node_sync(mByteArrayVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    byteArrNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto byteArrVariable = byteArrNode.as<VariableAccessor>();
    ASSERT_TRUE(byteArrVariable.has_value());
    byteArrVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "ByteArray"});
    byteArrVariable->set_display_name(LocalizedText{"", "ByteArray"});
    byteArrVariable->set_data_type(NodeId{DataTypeId::Byte});
    byteArrVariable->set_value_rank(ValueRank{1});  // one-dimensional array
    byteArrVariable->write_value_sync(Array<uint8_t>{1, 2, 3});
    byteArrVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mByteArrayVariableId);
    byteArrNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // Number-typed Variable: ns=mTestNamespaceIndex;i=1006
    // DataType = Number (abstract supertype of all numeric types).
    // Used for subtype-accepted testing (SVR-ATTR-WRITE-008).
    mNumberVariableId = NodeId{mTestNamespaceIndex, uint32_t{1006}};
    auto numNode = addressSpace.create_node_sync(mNumberVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    numNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto numVariable = numNode.as<VariableAccessor>();
    ASSERT_TRUE(numVariable.has_value());
    numVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "NumberVariable"});
    numVariable->set_display_name(LocalizedText{"", "NumberVariable"});
    numVariable->set_data_type(NodeId{DataTypeId::Number});
    numVariable->write_value_sync(double{0.0});
    numVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mNumberVariableId);
    numNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // DataType = UInteger (abstract supertype of the unsigned integer types only).
    // Used for abstract-subtype mismatch testing (SVR-ATTR-WRITE-010): writing a signed
    // integer (e.g. Int32) must be rejected with Bad_TypeMismatch.
    mUIntegerVariableId = NodeId{mTestNamespaceIndex, uint32_t{1014}};
    auto uintNode = addressSpace.create_node_sync(mUIntegerVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    uintNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto uintVariable = uintNode.as<VariableAccessor>();
    ASSERT_TRUE(uintVariable.has_value());
    uintVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "UIntegerVariable"});
    uintVariable->set_display_name(LocalizedText{"", "UIntegerVariable"});
    uintVariable->set_data_type(NodeId{DataTypeId::UInteger});
    uintVariable->write_value_sync(uint32_t{0});
    uintVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mUIntegerVariableId);
    uintNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // DataType = Duration (a non-builtin subtype of Double). Used to verify that the built-in base
    // type of a named subtype is enforced on Write (SVR-ATTR-WRITE-008/010): a non-Double value must be
    // rejected with Bad_TypeMismatch even though Duration is not itself a built-in type.
    mDurationVariableId = NodeId{mTestNamespaceIndex, uint32_t{1015}};
    auto durNode = addressSpace.create_node_sync(mDurationVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    durNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto durVariable = durNode.as<VariableAccessor>();
    ASSERT_TRUE(durVariable.has_value());
    durVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "DurationVariable"});
    durVariable->set_display_name(LocalizedText{"", "DurationVariable"});
    durVariable->set_data_type(NodeId{DataTypeId::Duration});
    durVariable->write_value_sync(double{1000.0});
    durVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mDurationVariableId);
    durNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // MaxAge test Variable: ns=mTestNamespaceIndex;i=1007
    // Used for maxAge read handler testing (SVR-ATTR-READ-001/002/003).
    mMaxAgeVariableId = NodeId{mTestNamespaceIndex, uint32_t{1007}};
    auto maxAgeNode = addressSpace.create_node_sync(mMaxAgeVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    maxAgeNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto maxAgeVariable = maxAgeNode.as<VariableAccessor>();
    ASSERT_TRUE(maxAgeVariable.has_value());
    maxAgeVariable->set_browse_name(QualifiedName{mTestNamespaceIndex, "MaxAgeTest"});
    maxAgeVariable->set_display_name(LocalizedText{"", "MaxAgeTest"});
    maxAgeVariable->set_data_type(NodeId{DataTypeId::Int32});
    maxAgeVariable->write_value_sync(int32_t{0});
    maxAgeVariable->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMaxAgeVariableId);
    maxAgeNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // --- Browse hierarchy children under TestFolder ---
    // Used by View service set compliance tests (Phase 5).
    // Gives TestFolder 6 children total: TestMethod + 3 Variables + 2 Objects.

    for (uint32_t i = 0; i < 3; ++i)
    {
      auto childId = NodeId{mTestNamespaceIndex, uint32_t{4000 + i}};
      mBrowseChildVariableIds.push_back(childId);
      auto childNode = addressSpace.create_node_sync(childId, NodeClass::Variable);
      // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
      // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
      // TypeDefinition found this fixture building twenty untyped nodes -- test data that
      // is not a conforming address space, so any test browsing it was reading a model
      // the specification forbids.
      childNode.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
      auto childVar = childNode.as<VariableAccessor>();
      ASSERT_TRUE(childVar.has_value());
      auto name = "BrowseChildVar" + std::to_string(i);
      childVar->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
      childVar->set_display_name(LocalizedText{"", name});
      childVar->set_data_type(NodeId{DataTypeId::Int32});
      childVar->write_value_sync(int32_t{100 + static_cast<int32_t>(i)});
      childVar->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
      folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, childId);
      // The Node primitive is one-sided, so the inverse half has to be added on the child or an
      // inverse Browse of it finds no owner at all (Part 3 section 5.6.4).
      childNode.add_reference_sync(
        NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, /*isForward=*/false);
    }

    for (uint32_t i = 0; i < 2; ++i)
    {
      auto childId = NodeId{mTestNamespaceIndex, uint32_t{4100 + i}};
      mBrowseChildObjectIds.push_back(childId);
      auto childNode = addressSpace.create_node_sync(childId, NodeClass::Object);
      // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
      // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
      // TypeDefinition found this fixture building twenty untyped nodes -- test data that
      // is not a conforming address space, so any test browsing it was reading a model
      // the specification forbids.
      childNode.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
      auto childObj = childNode.as<ObjectAccessor>();
      ASSERT_TRUE(childObj.has_value());
      auto name = "BrowseChildObj" + std::to_string(i);
      childObj->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
      childObj->set_display_name(LocalizedText{"", name});
      folderNode.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, childId);
    }

    // Duplicate BrowseName targets under BrowseChildObj0 for SVR-VIEW-TBP-002.
    mDuplicateNameParentId = mBrowseChildObjectIds[0];
    auto dupParentNode = addressSpace.find_node_sync(mDuplicateNameParentId);
    for (uint32_t i = 0; i < 2; ++i)
    {
      auto dupId = NodeId{mTestNamespaceIndex, uint32_t{4200 + i}};
      mDuplicateNameTargetIds.push_back(dupId);
      auto dupNode = addressSpace.create_node_sync(dupId, NodeClass::Variable);
      // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
      // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
      // TypeDefinition found this fixture building twenty untyped nodes -- test data that
      // is not a conforming address space, so any test browsing it was reading a model
      // the specification forbids.
      dupNode.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
      auto dupVar = dupNode.as<VariableAccessor>();
      ASSERT_TRUE(dupVar.has_value());
      dupVar->set_browse_name(QualifiedName{mTestNamespaceIndex, "DuplicateTarget"});
      dupVar->set_display_name(LocalizedText{"", "DuplicateTarget" + std::to_string(i)});
      dupVar->set_data_type(NodeId{DataTypeId::Int32});
      dupVar->write_value_sync(int32_t{200 + static_cast<int32_t>(i)});
      dupVar->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
      dupParentNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, dupId);
      // The Node primitive is one-sided, so the inverse half has to be added on the child or an
      // inverse Browse of it finds no owner at all (Part 3 section 5.6.4).
      dupNode.add_reference_sync(
        NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mDuplicateNameParentId}, /*isForward=*/false);
    }

    // Int32 array variable: ns=mTestNamespaceIndex;i=1008
    // Used for SVR-MI-GEN-044 (array deadband testing).
    mArrayVariableId = NodeId{mTestNamespaceIndex, uint32_t{1008}};
    auto arrayNode = addressSpace.create_node_sync(mArrayVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    arrayNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto arrayVar = arrayNode.as<VariableAccessor>();
    ASSERT_TRUE(arrayVar.has_value());
    arrayVar->set_browse_name(QualifiedName{mTestNamespaceIndex, "ArrayInt32"});
    arrayVar->set_display_name(LocalizedText{"", "ArrayInt32"});
    arrayVar->set_data_type(NodeId{DataTypeId::Int32});
    arrayVar->set_value_rank(ValueRank{1});  // one-dimensional
    arrayVar->write_value_sync(Array<int32_t>{100, 200, 300});
    arrayVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mArrayVariableId);
    arrayNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // Variable with MinimumSamplingInterval: ns=mTestNamespaceIndex;i=1009
    // Used for SVR-MI-GEN-005 (minimum sampling interval testing).
    mMinSamplingVariableId = NodeId{mTestNamespaceIndex, uint32_t{1009}};
    auto minSampNode = addressSpace.create_node_sync(mMinSamplingVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    minSampNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto minSampVar = minSampNode.as<VariableAccessor>();
    ASSERT_TRUE(minSampVar.has_value());
    minSampVar->set_browse_name(QualifiedName{mTestNamespaceIndex, "MinSamplingVar"});
    minSampVar->set_display_name(LocalizedText{"", "MinSamplingVar"});
    minSampVar->set_data_type(NodeId{DataTypeId::Int32});
    minSampVar->write_value_sync(int32_t{0});
    minSampVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    minSampVar->set_minimum_sampling_interval(500.0);
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMinSamplingVariableId);
    minSampNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);

    // Deletable variable: ns=mTestNamespaceIndex;i=1010
    // Used for SVR-MI-GEN-090 (node deletion monitoring test).
    mDeletableVariableId = NodeId{mTestNamespaceIndex, uint32_t{1010}};
    auto delNode = addressSpace.create_node_sync(mDeletableVariableId, NodeClass::Variable);
    // Part 3 section 5.5: every Object and Variable sources exactly one HasTypeDefinition.
    // Added when ComplianceWithNodes.EverySampledObjectAndVariableSourcesExactlyOne-
    // TypeDefinition found this fixture building twenty untyped nodes -- test data that
    // is not a conforming address space, so any test browsing it was reading a model
    // the specification forbids.
    delNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
    auto delVar = delNode.as<VariableAccessor>();
    ASSERT_TRUE(delVar.has_value());
    delVar->set_browse_name(QualifiedName{mTestNamespaceIndex, "DeletableVar"});
    delVar->set_display_name(LocalizedText{"", "DeletableVar"});
    delVar->set_data_type(NodeId{DataTypeId::Int32});
    delVar->write_value_sync(int32_t{7});
    delVar->set_access_level(
      AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
    // Part 3 section 5.6.4: owned by HasComponent, both halves (see mWritableVariableId).
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mDeletableVariableId);
    delNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent},
      ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}},
      /*isForward=*/false);
  }

  std::shared_ptr<default_ns::Namespace> mTestNamespace;
  uint16_t mTestNamespaceIndex{0};
  NodeId mWritableVariableId;
  NodeId mFullAccessVariableId;
  NodeId mTestFolderId;
  NodeId mTestMethodId;
  NodeId mNonExecutableMethodId;
  NodeId mNoHandlerMethodId;
  NodeId mNoArgsMethodId;
  NodeId mEncryptionRequiredMethodId;
  NodeId mOtherObjectId;
  NodeId mTestObjectTypeId;
  NodeId mObjectTypeMethodId;
  NodeId mTypedObjectId;
  NodeId mWritableDisplayNameNodeId;
  NodeId mEncryptionRequiredVariableId;
  NodeId mEnumVariableId;
  NodeId mByteArrayVariableId;
  NodeId mNumberVariableId;
  NodeId mUIntegerVariableId;
  NodeId mDurationVariableId;
  NodeId mMaxAgeVariableId;
  NodeId mArrayVariableId;
  NodeId mMinSamplingVariableId;
  NodeId mDeletableVariableId;

  // Browse hierarchy children under TestFolder (Phase 5 View tests).
  std::vector<NodeId> mBrowseChildVariableIds;  // 3 Variables via HasComponent
  std::vector<NodeId> mBrowseChildObjectIds;  // 2 Objects via Organizes
  NodeId mDuplicateNameParentId;  // BrowseChildObj0
  std::vector<NodeId> mDuplicateNameTargetIds;  // 2 Variables with same BrowseName
};

// ---------------------------------------------------------------------------
// ComplianceSecured: full PKI setup, multiple security endpoints
// ---------------------------------------------------------------------------
class ComplianceSecured : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mCrypto = create_default_crypto([]() { return ua::SecureString{"password"}; });

    // Server certificate.
    Crypto::Name subject;
    subject.commonName = "ComplianceSecured Server";
    UtcTime expiry{2050, 1, 1, 0, 0, 0};
    Crypto::SubjectAlternateName altName;
    altName.uris.push_back("urn:test:compliance:server");
    altName.hostnames.push_back("localhost");
    altName.hostnames.push_back("127.0.0.1");

    auto serverCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      subject, expiry, altName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(serverCertResult.is_good());
    auto [serverKeys, serverCert] = std::move(serverCertResult).value();
    mServerCert = std::move(serverCert);

    // Client certificate.
    Crypto::Name clientSubject;
    clientSubject.commonName = "ComplianceSecured Client";
    Crypto::SubjectAlternateName clientAltName;
    clientAltName.uris.push_back("urn:test:compliance:client");
    clientAltName.hostnames.push_back("localhost");

    auto clientCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
      clientSubject, expiry, clientAltName, CertificateType::RsaSha256Application, 2048);
    ASSERT_TRUE(clientCertResult.is_good());
    auto [clientKeys, clientCert] = std::move(clientCertResult).value();

    // Temp directories for cert stores.
    mTempDir = std::filesystem::temp_directory_path() /
               ("ua_compliance_test_" + Guid::create_and_generate().as_string());
    std::filesystem::create_directories(mTempDir);

    // Server cert store: holds server app cert, trusts client cert.
    auto serverStorePath = mTempDir / "server_store";
    std::filesystem::create_directories(serverStorePath);

    TrustListValidationOptions validationOptions;
    mServerCertStore = CertificateStoreFiles::create(mServerThreadPool.executor(),
      mCrypto,
      {.trustListPath = serverStorePath, .validationOptions = validationOptions});

    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = mServerCert;
      appCert.keys = std::move(serverKeys);
      mServerCertStore->add_to_application_certificates_sync(appCert);
    }
    mServerCertStore->add_to_trusted_certificates_sync(clientCert);

    // Client cert store: holds client app cert, trusts server cert.
    auto clientStorePath = mTempDir / "client_store";
    std::filesystem::create_directories(clientStorePath);

    mClientCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
      mCrypto,
      {.trustListPath = clientStorePath, .validationOptions = validationOptions});

    {
      CertificateStore::ApplicationCertificate appCert;
      appCert.certificateType = CertificateType::RsaSha256Application;
      appCert.certificate = clientCert;
      appCert.keys = std::move(clientKeys);
      mClientCertStore->add_to_application_certificates_sync(appCert);
    }
    mClientCertStore->add_to_trusted_certificates_sync(mServerCert);

    // Server.
    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;
    configure_secured_server(appCfg);
    // Use the production authentication interval. A shorter fixture-only interval made an inline
    // authenticator's posted completion race its fixed timer under instrumentation and session churn.
    // Dedicated configuration coverage overrides this with a non-default interval and proves the
    // public field end to end.
    mAuthenticator = std::make_shared<MutableClaimAuthenticator>();
    server::ServerComponents components{.crypto = mCrypto,
      .applicationGroupCertificateStore = mServerCertStore,
      .authenticator = mAuthenticator,
      .roleConfiguration = RoleConfiguration::from_well_known_grants(
        {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}}),
      .logSink = mServerLogSink,
      .logLevel = LogLevel::Debug};
    configure_components(components);

    server::CreateConfig serverCreateCfg{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
    configure_server_create_config(serverCreateCfg);

    mServer.emplace(
      Server::create(mServerThreadPool.executor(), std::move(serverCreateCfg), std::move(components)));

    transport::BindAddress bind;
    bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
    bind.address = "127.0.0.1:0";
    mListenerHandle = mServer->listen_sync(std::move(bind), {});

    // None endpoint
    ServerEndpointConfig noneEp;
    noneEp.name = "None";
    noneEp.messageSecurityMode = MessageSecurityMode::None;
    noneEp.securityPolicyId = SecurityPolicyId::None;
    noneEp.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(noneEp));

    // Basic256Sha256 Sign
    ServerEndpointConfig signEp;
    signEp.name = "Basic256Sha256_Sign";
    signEp.messageSecurityMode = MessageSecurityMode::Sign;
    signEp.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    signEp.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(signEp));

    // Basic256Sha256 SignAndEncrypt
    ServerEndpointConfig signEncryptEp;
    signEncryptEp.name = "Basic256Sha256_SignAndEncrypt";
    signEncryptEp.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
    signEncryptEp.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    signEncryptEp.userIdentityTokens.push_back(
      create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
    mServer->add_endpoint(mListenerHandle, std::move(signEncryptEp));

    mServer->start_sync();

    auto urls = mServer->advertised_urls(mListenerHandle);
    ASSERT_FALSE(urls.empty());
    mEndpointUrl = urls.front().str();

    // Client.
    auto clientAppCfg = ua::test_utils::create_test_config();
    configure_client_application(clientAppCfg);
    auto clientCfg = ua::test_utils::scale_service_timeout(client::CreateConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)});
    mClient.emplace(Client::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mClientCertStore,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug}));
  }

  void TearDown() override
  {
    if (mServer)
      (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
    mClient.reset();
    mServer.reset();
    ::ua::test_utils::stop_pool_in_teardown(mClientThreadPool, "client");
    ::ua::test_utils::stop_pool_in_teardown(mServerThreadPool, "server");

    std::error_code ec;
    std::filesystem::remove_all(mTempDir, ec);
  }

  /// Override to customize server application config before server is created.
  virtual void configure_secured_server(ApplicationConfig& /*appCfg*/)
  {}

  /// Override to customize the full server create config (server capabilities, etc.).
  virtual void configure_server_create_config(server::CreateConfig& /*cfg*/)
  {}

  /// Override to customize the client's ApplicationConfig before
  /// the Client is constructed (e.g. to set a specific `mApplicationUri`
  /// so the ClientDescription URI matches the client cert SAN URI for
  /// Part-18 Application-criteria tests).
  virtual void configure_client_application(ApplicationConfig& appCfg)
  {
    // The default ComplianceSecured own certificate is allocated above with this SAN URI. Keep the
    // ApplicationDescription identity bound to that certificate (Part 6 section 6.2.2); specialized fixtures
    // may override when they deliberately allocate/use another application identity.
    appCfg.application_description_part().applicationUri = "urn:test:compliance:client";
  }

  /// Override to customize the server components (authenticator, Role configuration, user-token store).
  virtual void configure_components(server::ServerComponents& /*components*/)
  {}

  void set_authentication_claims(std::unordered_map<std::string, std::string> claims)
  {
    mAuthenticator->set_claims(std::move(claims));
  }

  std::shared_ptr<const Crypto> mCrypto;
  std::shared_ptr<MutableClaimAuthenticator> mAuthenticator;
  std::shared_ptr<const X509Certificate> mServerCert;
  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::shared_ptr<CertificateStore> mServerCertStore;
  // Server log sink, installed at construction (there is no runtime sink setter). A CapturingLogSink
  // so tests that assert on server logs can inspect it; it forwards to test_log_sink() for failure
  // dumps, so this is transparent to fixtures that do not read it.
  std::shared_ptr<CapturingLogSink> mServerLogSink{std::make_shared<CapturingLogSink>()};
  std::shared_ptr<CertificateStore> mClientCertStore;
  std::filesystem::path mTempDir;
  std::optional<Server> mServer;
  ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
};

// ---------------------------------------------------------------------------
// ComplianceSecuredWithSession: authenticated channel + anonymous session
// ---------------------------------------------------------------------------
class ComplianceSecuredWithSession : public ComplianceSecured
{
protected:
  void SetUp() override
  {
    ComplianceSecured::SetUp();
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    cfg.serverCertificate = mServerCert;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(cfg)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceSecuredTest"}));
    mSession->activate_sync();
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// ---------------------------------------------------------------------------
// ComplianceSecureChannel: inherits ComplianceSecured, adds channel state
// inspection helpers via TestAccess. No session opened by default.
// ---------------------------------------------------------------------------
class ComplianceSecureChannel : public ComplianceSecured
{
protected:
  void configure_secured_server(ApplicationConfig& appCfg) override
  {
    // Short minimum lifetime so renewal tests don't take minutes.
    appCfg.stack_limits().secureChannelMinimumLifetime = std::chrono::milliseconds{1000};
  }

  /// Open a channel with a given security mode + policy.
  SecureChannel open_channel(MessageSecurityMode mode, SecurityPolicyId policy)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
      cfg.serverCertificate = mServerCert;
    return mClient->core().open_channel_sync(std::move(cfg));
  }

  /// Open channel with short requested lifetime (for renewal tests).
  SecureChannel open_channel_short_lifetime(
    MessageSecurityMode mode, SecurityPolicyId policy, std::chrono::milliseconds lifetime)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = policy;
    cfg.requestedLifetime = lifetime;
    if (mode != MessageSecurityMode::None)
      cfg.serverCertificate = mServerCert;
    return mClient->core().open_channel_sync(std::move(cfg));
  }

  /// Open channel with a TransportDecorator to get a FuzzTransportConnection.
  SecureChannel open_channel_with_transport_decorator(MessageSecurityMode mode, SecurityPolicyId policy,
    std::shared_ptr<opcua_fuzzer::FuzzTransportConnection>& outFuzz)
  {
    ua::client::ClientTestHooks hooks;
    hooks.transportDecorator = [&outFuzz](std::shared_ptr<TransportConnection> inner)
    {
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzTransportConnection>(std::move(inner));
      outFuzz = fuzz;
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));

    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
      cfg.serverCertificate = mServerCert;
    return mClient->core().open_channel_sync(std::move(cfg));
  }

  /// Open channel with a SecurityPolicyFactory to get a FuzzSecurityPolicy.
  SecureChannel open_channel_with_security_policy_factory(MessageSecurityMode mode, SecurityPolicyId policy,
    std::shared_ptr<opcua_fuzzer::FuzzSecurityPolicy>& outFuzz)
  {
    ua::client::ClientTestHooks hooks;
    hooks.securityPolicyFactory = [&outFuzz](SecurityPolicyId policyId) -> std::shared_ptr<SecurityPolicy>
    {
      auto inner = SecurityPolicy::create(policyId);
      auto fuzz = std::make_shared<opcua_fuzzer::FuzzSecurityPolicy>(std::move(inner));
      outFuzz = fuzz;
      return fuzz;
    };
    ua::client::CoreClientTestAccess::set_test_hooks(mClient->core(), std::move(hooks));

    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
      cfg.serverCertificate = mServerCert;
    return mClient->core().open_channel_sync(std::move(cfg));
  }
};

// ---------------------------------------------------------------------------
// ComplianceSecureChannelLimited: standalone fixture with constrained server
// limits for resource-exhaustion tests.
// ---------------------------------------------------------------------------
class ComplianceSecureChannelLimited : public ComplianceSecured
{
protected:
  void configure_secured_server(ApplicationConfig& appCfg) override
  {
    // Short minimum lifetime so resource-exhaustion tests don't take forever.
    appCfg.stack_limits().secureChannelMinimumLifetime = std::chrono::milliseconds{1000};
  }

  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.maxSecureChannels = mMaxSecureChannels;
    cfg.server.maxConnections = mMaxConnections;
    // Disable connection throttling so tests can open many connections quickly.
    cfg.server.connectionThrottling.enabled = false;
  }

  /// Open a channel (None policy for simplicity in resource tests).
  SecureChannel open_channel_none()
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::None;
    cfg.securityPolicyId = SecurityPolicyId::None;
    return mClient->core().open_channel_sync(std::move(cfg));
  }

  /// Open a channel with auth (for session tests).
  SecureChannel open_channel_auth()
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
    cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
    cfg.serverCertificate = mServerCert;
    return mClient->core().open_channel_sync(std::move(cfg));
  }

  /// Create a second client (for multi-connection tests).
  Client create_additional_client()
  {
    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = "urn:test:compliance:client";
    auto clientCfg = ua::test_utils::scale_service_timeout(client::CreateConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)});
    auto client = Client::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mClientCertStore,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});
    return client;
  }

  uint32_t mMaxSecureChannels{2};
  uint32_t mMaxConnections{4};  // needs headroom: each channel uses a connection + discovery may use one
};

// ComplianceSecureChannelConnectionLimit: variant of ComplianceSecureChannelLimited where
// mMaxSecureChannels is set above mMaxConnections so that the connection limit is the effective
// rejection boundary (no eviction at the MaxSecureChannels level).
class ComplianceSecureChannelConnectionLimit : public ComplianceSecureChannelLimited
{
protected:
  ComplianceSecureChannelConnectionLimit()
  {
    mMaxSecureChannels = mMaxConnections + 4;  // high enough that eviction never triggers
  }
};

// ---------------------------------------------------------------------------
// ComplianceSession: inherits ComplianceSecured, short session timeout,
// helpers for session state inspection via SessionTestAccess.
// ---------------------------------------------------------------------------
class ComplianceSession : public ComplianceSecured
{
protected:
  void configure_secured_server(ApplicationConfig& appCfg) override
  {
    // Short minimum session timeout so timeout tests don't take minutes.
    appCfg.stack_limits().sessionMinimumTimeout = std::chrono::milliseconds{1000};
    appCfg.stack_limits().sessionMaximumTimeout = std::chrono::milliseconds{60000};
  }

  /// Open a channel with a given security mode + policy.
  SecureChannel open_channel(MessageSecurityMode mode, SecurityPolicyId policy)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
      cfg.serverCertificate = mServerCert;
    return mClient->core().open_channel_sync(std::move(cfg));
  }
};

// ---------------------------------------------------------------------------
// ComplianceSessionLimited: constrained session limits for resource-exhaustion
// and identity throttling tests.
// ---------------------------------------------------------------------------
class ComplianceSessionLimited : public ComplianceSecured
{
protected:
  void configure_secured_server(ApplicationConfig& appCfg) override
  {
    appCfg.stack_limits().sessionMinimumTimeout = std::chrono::milliseconds{1000};
    appCfg.stack_limits().sessionMaximumTimeout = std::chrono::milliseconds{60000};
  }

  void configure_server_create_config(server::CreateConfig& cfg) override
  {
    cfg.server.server_capabilities().maxSessions = mMaxSessions;
    cfg.server.identityThrottling.enabled = true;
    cfg.server.identityThrottling.maxFailedAttemptsBeforeLockout = mMaxFailedAttempts;
    cfg.server.identityThrottling.lockoutDuration = mLockoutDuration;
  }

  /// Open a channel with a given security mode + policy.
  SecureChannel open_channel(MessageSecurityMode mode, SecurityPolicyId policy)
  {
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = policy;
    if (mode != MessageSecurityMode::None)
      cfg.serverCertificate = mServerCert;
    return mClient->core().open_channel_sync(std::move(cfg));
  }

  /// Create a second client (for multi-connection tests).
  Client create_additional_client()
  {
    auto clientAppCfg = ua::test_utils::create_test_config();
    clientAppCfg.application_description_part().applicationUri = "urn:test:compliance:client";
    auto clientCfg = ua::test_utils::scale_service_timeout(client::CreateConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(clientAppCfg)});
    auto client = Client::create(mClientThreadPool.executor(),
      std::move(clientCfg),
      ua::client::ClientComponents{.crypto = mCrypto,
        .applicationGroupCertificateStore = mClientCertStore,
        .logSink = test_log_sink(),
        .logLevel = LogLevel::Debug});
    return client;
  }

  uint32_t mMaxSessions{2};
  uint32_t mMaxFailedAttempts{3};
  std::chrono::seconds mLockoutDuration{5};
};

#endif  // COMPLIANCE_HELPERS_H
