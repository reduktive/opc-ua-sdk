// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Phase 6: Method Service Set - Compliance Integration Tests
///
/// Tests covering Part 4 Method Call requirements (METH-GEN-*, SVR-METH-CALL-*).
///
/// The server delegates argument validation to the method handler (via MethodAdapter).
/// Tests that validate argument counts/types therefore exercise the full stack:
/// client -> server -> MethodAdapter handler -> callback -> server -> client.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_session_method_services.h"

#include "ua_session_view_services.h"

#include "ua_argument.h"
#include "ua_array.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_data_value.h"
#include "ua_guid.h"
#include "ua_method_id.h"
#include "ua_objecttype_id.h"
#include "ua_ref_structure.h"
#include "ua_reference_description.h"
#include "ua_server.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_transport_address.h"
#include "ua_variant.h"

#include "security/ua_server_authentication.h"
#include "security/ua_role_configuration.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

// ===========================================================================
// Fixture: ComplianceMethodOpLimited - server with MaxNodesPerMethodCall = 1
// ===========================================================================
class ComplianceMethodOpLimited : public ::testing::Test
{
protected:
  void SetUp() override
  {

    auto appCfg = ua::test_utils::create_test_config();
    appCfg.allowInsecureEndpoints = true;

    server::ServerConfig serverCfg;
    serverCfg.server_capabilities().operationLimits.maxNodesPerMethodCall = 1;

    server::CreateConfig createCfg{.identity = ApplicationIdentity::load_default(),
      .application = std::move(appCfg),
      .server = std::move(serverCfg)};

    auto logSink = test_log_sink();
    mServer.emplace(server::Server::create(mServerThreadPool.executor(),
      std::move(createCfg),
      server::ServerComponents{.crypto = ua::test_helpers::test_crypto(),
        .authenticator = std::make_shared<AnonymousAuthenticator>(),
        .roleConfiguration = RoleConfiguration::from_well_known_grants(
          {{WellKnownRole::SecurityAdmin, IdentityCriteriaType::Anonymous}}),
        .logSink = logSink,
        .logLevel = LogLevel::Debug}));

    // Create a test method.
    auto addressSpace = mServer->address_space();
    mNamespace = default_ns::Namespace::create("urn:test:method:limited", mServerThreadPool.executor());
    mNamespaceIndex = addressSpace.add_namespace_sync(mNamespace);

    mObjectId = NodeId{mNamespaceIndex, uint32_t{6000}};
    auto objNode = addressSpace.create_node_sync(mObjectId, NodeClass::Object);
    auto obj = objNode.as<ObjectAccessor>();
    ASSERT_TRUE(obj.has_value());
    obj->set_browse_name(QualifiedName{mNamespaceIndex, "LimitTestObject"});
    obj->set_display_name(LocalizedText{"", "LimitTestObject"});

    mMethodId = NodeId{mNamespaceIndex, uint32_t{6001}};
    auto methodNode = addressSpace.create_node_sync(mMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    ASSERT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{mNamespaceIndex, "LimitTestMethod"});
    method->set_display_name(LocalizedText{"", "LimitTestMethod"});
    method->set_executable(true);
    objNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMethodId);
    {
      auto* callSource = mNamespace->find_node<Node>(mMethodId)->method_call_source();
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
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceMethodOpLimited"}));
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

  boost::asio::thread_pool mServerThreadPool;
  boost::asio::thread_pool mClientThreadPool;
  std::optional<server::Server> mServer;
  server::ListenerHandle mListenerHandle{0};
  std::string mEndpointUrl;
  std::optional<Client> mClient;
  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mNamespaceIndex{0};
  NodeId mObjectId;
  NodeId mMethodId;
};

// ===========================================================================
// Fixture: ComplianceMethodDenyCall - RolePermissions deny Call operations
//
// Uses ComplianceSecured so configure_components can grant the Anonymous Role.
// ===========================================================================
class ComplianceMethodDenyCall : public ComplianceSecured
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    // Open a None channel + session (simplest path).
    CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = MessageSecurityMode::None;
    cfg.securityPolicyId = SecurityPolicyId::None;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(cfg)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ComplianceMethodDenyCall"}));
    mSession->activate_sync();

    // Create a test method on the server.
    auto addressSpace = mServer->address_space();
    mTestNamespace = default_ns::Namespace::create("urn:test:method:deny", mServerThreadPool.executor());
    mTestNamespaceIndex = addressSpace.add_namespace_sync(mTestNamespace);

    mDenyTestObjectId = NodeId{mTestNamespaceIndex, uint32_t{5000}};
    auto objNode = addressSpace.create_node_sync(mDenyTestObjectId, NodeClass::Object);
    auto obj = objNode.as<ObjectAccessor>();
    ASSERT_TRUE(obj.has_value());
    obj->set_browse_name(QualifiedName{mTestNamespaceIndex, "DenyTestObject"});
    obj->set_display_name(LocalizedText{"", "DenyTestObject"});

    mDenyTestMethodId = NodeId{mTestNamespaceIndex, uint32_t{5001}};
    auto methodNode = addressSpace.create_node_sync(mDenyTestMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    ASSERT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{mTestNamespaceIndex, "DenyTestMethod"});
    method->set_display_name(LocalizedText{"", "DenyTestMethod"});
    method->set_executable(true);
    RolePermissionType anonymousPermissions;
    anonymousPermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymousPermissions.permissions() =
      PermissionType{{PermissionType::Bit::Browse, PermissionType::Bit::Read}};
    method->set_role_permissions(std::vector<RolePermissionType>{anonymousPermissions});
    objNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mDenyTestMethodId);
    {
      auto* callSource = mTestNamespace->find_node<Node>(mDenyTestMethodId)->method_call_source();
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
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  std::shared_ptr<default_ns::Namespace> mTestNamespace;
  uint16_t mTestNamespaceIndex{0};
  NodeId mDenyTestObjectId;
  NodeId mDenyTestMethodId;
  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// ===========================================================================
// Positive smoke tests
// ===========================================================================

// Call method with valid args on the correct object -> Good status, output args returned.
TEST_F(ComplianceWithNodes, CallMethodSuccess)
{
  auto result = mSession->methods().try_call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{3}}, Variant{int32_t{4}}}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
}

// Call method with valid args -> output arguments contain the sum.
TEST_F(ComplianceWithNodes, CallMethodWithOutputArgs)
{
  auto result = mSession->methods().try_call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{10}}, Variant{int32_t{32}}}));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_THAT(resp.results()[0], Good());
  ASSERT_EQ(resp.results()[0].output_arguments().size(), 1u);
  EXPECT_EQ(resp.results()[0].output_arguments()[0].as<int32_t>(), 42);
}

// Call multiple methods in a single request -> results ordered, all succeed.
TEST_F(ComplianceWithNodes, CallMultipleMethods)
{
  auto result = mSession->methods().try_call_sync(
    CallRequestBuilder()
      .call(mTestFolderId, mTestMethodId, {Variant{int32_t{5}}, Variant{int32_t{7}}})
      .call(mTestFolderId, mNoArgsMethodId));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  // First result: Add method
  EXPECT_THAT(resp.results()[0], Good());
  ASSERT_EQ(resp.results()[0].output_arguments().size(), 1u);
  EXPECT_EQ(resp.results()[0].output_arguments()[0].as<int32_t>(), 12);

  // Second result: NoArgs method
  EXPECT_THAT(resp.results()[1], Good());
}

// ===========================================================================
// Positive requirement tests
// ===========================================================================

// Requirement: SVR-METH-GEN-001 (SHALL)
// A Method shall be a component of an Object.
// Spec: Part 4, section 5.11.1, line 4110
// @relation(SVR-METH-CALL-061, SVR-METH-GEN-001, scope=function)
TEST_F(ComplianceWithNodes, METH_GEN_001_MethodIsComponentOfObject)
{
  // TestMethod is a component of TestFolder (Object) via HasComponent.
  // Calling it with TestFolder as objectId should succeed.
  auto result = mSession->methods().try_call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
}

// Requirement: SVR-METH-CALL-010 (SHALL)
// The objectId shall be that of the Object or ObjectType on which the Method is invoked.
// Spec: Part 4, section 5.11.2.2, line 4150
// @relation(SVR-METH-CALL-010, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_010_ObjectIdIsObjectOrObjectType)
{
  // Verify both Object and ObjectType are accepted as objectId.

  // Case 1: objectId is an Object (TestFolder) with direct HasComponent to method.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{1}}}));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], Good()) << "Object as objectId should be accepted";
  }

  // Case 2: objectId is an ObjectType (TestObjectType) with HasComponent to method.
  {
    auto result = mSession->methods().try_call_sync(call_method(mTestObjectTypeId, mObjectTypeMethodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], Good()) << "ObjectType as objectId should be accepted";
  }
}

// Requirement: SVR-METH-CALL-011 (SHALL)
// In the case of an ObjectType, the ObjectType or a super type of the ObjectType shall be
// the source of a HasComponent Reference (or subtype of HasComponent Reference) to the Method.
// Spec: Part 4, section 5.11.2.2, line 4152
// @relation(SVR-METH-CALL-011, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_011_ObjectTypeHasComponentToMethod)
{
  // TestObjectType has a direct HasComponent reference to ObjectTypeMethod.
  // Calling with the ObjectType as objectId shall succeed.
  auto result = mSession->methods().try_call_sync(call_method(mTestObjectTypeId, mObjectTypeMethodId));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Calling method via HasComponent on ObjectType should succeed";
}

// Requirement: SVR-METH-CALL-012 (SHALL)
// In the case of an Object, the Object or the ObjectType of the Object or a super type
// of that ObjectType shall be the source of a HasComponent Reference to the Method.
// Spec: Part 4, section 5.11.2.2, line 4156
// @relation(SVR-METH-CALL-012, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_012_MethodViaObjectType)
{
  // TypedObject has HasTypeDefinition -> TestObjectType.
  // TestObjectType has HasComponent -> ObjectTypeMethod.
  // TypedObject does NOT have a direct HasComponent to ObjectTypeMethod.
  // Calling ObjectTypeMethod with TypedObject as objectId should succeed
  // because the server resolves the method via the Object's ObjectType.
  auto result = mSession->methods().try_call_sync(call_method(mTypedObjectId, mObjectTypeMethodId));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good()) << "Calling method resolved via Object's ObjectType should succeed";
}

// Requirement: SVR-METH-CALL-031 (SHALL NOT)
// Good StatusCodes with sub-status shall not be used as statusCode since many programming
// language bindings would cause such codes to throw an exception.
// Spec: Part 4, section 5.11.2.4, line 4240
// @relation(SVR-METH-CALL-031, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_031_NoGoodSubStatus)
{
  auto result = mSession->methods().try_call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);

  auto status = resp.results()[0].status_code();
  EXPECT_TRUE(status.is_good());
  // The status should be exactly Good (0x00000000), not Good with sub-status bits.
  EXPECT_EQ(status.as_uint32(), 0u)
    << "StatusCode should be plain Good (0x00000000), not Good with sub-status";
}

// ===========================================================================
// Negative requirement tests
// ===========================================================================

// Requirement: SVR-METH-CALL-021 (SHALL)
// The outputArguments list shall be empty if the statusCode Severity is Bad.
// Spec: Part 4, section 5.11.2.2, line 4210
// @relation(SVR-METH-CALL-021, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_021_OutputArgsEmptyOnBadStatus)
{
  // Call the Add method with wrong number of arguments -> Bad status.
  // The output arguments list should be empty.
  auto result = mSession->methods().try_call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}}));  // Only 1 arg, needs 2.
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  ASSERT_TRUE(resp.results()[0].status_code().is_bad()) << "Operation should fail with bad status";
  EXPECT_TRUE(resp.results()[0].output_arguments().empty())
    << "Output arguments shall be empty when statusCode severity is Bad";
}

// Requirement: SVR-METH-CALL-040 (SHALL return)
// Bad_NodeIdInvalid - Used to indicate that the specified Object is not valid.
// Spec: Part 4, section 5.11.2.4, line 4246
// @relation(SVR-METH-CALL-040, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_040_BadNodeIdInvalid)
{
  // Use a NodeId that refers to a Variable (not an Object/ObjectType) as objectId.
  // The objectId is syntactically valid but not valid as an Object reference.
  auto result = mSession->methods().try_call_sync(call_method(mWritableVariableId, mTestMethodId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdInvalid))
    << "Server shall return BadNodeIdInvalid when objectId is not an Object or ObjectType";
}

// Requirement: SVR-METH-CALL-041 (SHALL return)
// Bad_NodeIdUnknown - Used to indicate that the specified Object is not valid.
// Spec: Part 4, section 5.11.2.4, line 4248
// @verifies CL-METH-002
// @relation(CL-METH-002, SVR-METH-CALL-041, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_041_BadNodeIdUnknown)
{
  // Use a well-formed but non-existent NodeId as objectId.
  auto unknownObjectId = NodeId{mTestNamespaceIndex, uint32_t{99999}};
  auto result = mSession->methods().try_call_sync(call_method(unknownObjectId, mTestMethodId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdUnknown))
    << "Server shall return BadNodeIdUnknown when objectId does not exist";
}

// Requirement: SVR-METH-CALL-041b (SHALL return) (CTT Method Call/Err-002)
// Bad_MethodInvalid - a methodId that does not resolve to an existing node is not a valid method for
// the Call, even when the objectId is valid. (Not Bad_NodeIdUnknown, which is reserved for the object.)
// Spec: Part 4, section 5.11.2.
// @verifies CL-METH-002
// @relation(CL-METH-002, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_041b_BadMethodInvalidForUnknownMethod)
{
  // Valid object (TestFolder), well-formed but non-existent methodId.
  auto unknownMethodId = NodeId{mTestNamespaceIndex, uint32_t{88888}};
  auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, unknownMethodId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadMethodInvalid))
    << "Server shall return BadMethodInvalid when methodId does not refer to an existing method";
}

// Requirement: SVR-METH-CALL-042 (SHALL return)
// Bad_NotExecutable - The executable Attribute does not allow the execution of the Method.
// Spec: Part 4, section 5.11.2.4, line 4250
// @relation(SVR-METH-CALL-042, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_042_BadNotExecutable)
{
  // NonExecutableMethod has Executable=false.
  // The server should check the Executable attribute and reject the call.
  auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, mNonExecutableMethodId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNotExecutable))
    << "Server shall return BadNotExecutable when Executable attribute is false";
}

// Requirement: SVR-METH-CALL-043 (SHALL return)
// Bad_ArgumentsMissing - The Client did not specify all of the non-optional input arguments.
// Spec: Part 4, section 5.11.2.4, line 4251
// @relation(SVR-METH-CALL-043, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_043_BadArgumentsMissing)
{
  // TestMethod expects 2 Int32 arguments. Provide only 1.
  auto result =
    mSession->methods().try_call_sync(call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadArgumentsMissing))
    << "Server shall return BadArgumentsMissing when required arguments are missing";
}

// Requirement: SVR-METH-CALL-044 (SHALL return)
// Bad_TooManyArguments - The Client specified more input arguments than defined.
// Spec: Part 4, section 5.11.2.4, line 4252
// @relation(SVR-METH-CALL-044, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_044_BadTooManyArguments)
{
  // TestMethod expects 2 Int32 arguments. Provide 3.
  auto result = mSession->methods().try_call_sync(call_method(
    mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}, Variant{int32_t{3}}}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTooManyArguments))
    << "Server shall return BadTooManyArguments when too many arguments provided";
}

// Requirement: SVR-METH-CALL-045 (SHALL return)
// Bad_InvalidArgument - One or more of the input arguments are invalid.
// The inputArgumentResults contain the specific status code for each invalid argument.
// Spec: Part 4, section 5.11.2.4, line 4253
// @verifies CL-METH-005, CL-METH-003
// @relation(CL-METH-003, CL-METH-005, SVR-METH-CALL-045, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_045_BadInvalidArgument)
{
  // TestMethod expects 2 Int32 arguments. Provide a String for the first.
  auto result = mSession->methods().try_call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{String{"not an int"}}, Variant{int32_t{2}}}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadInvalidArgument))
    << "Server shall return BadInvalidArgument when input argument type is wrong";
  // inputArgumentResults should indicate which argument failed.
  ASSERT_GE(resp.results()[0].input_argument_results().size(), 1u);
  EXPECT_THAT(resp.results()[0].input_argument_results()[0], HasStatus(Status::BadTypeMismatch))
    << "First argument should have BadTypeMismatch";
}

// Requirement: SVR-METH-CALL-046 (SHALL return)
// Bad_UserAccessDenied - Access denied for the current user.
// Spec: Part 4, section 5.11.2.4, line 4256
// @relation(SVR-METH-CALL-046, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceMethodDenyCall, METH_CALL_046_BadUserAccessDenied)
{
  auto result = mSession->methods().try_call_sync(call_method(mDenyTestObjectId, mDenyTestMethodId));

  if (result.is_good())
  {
    // Service succeeded - check operation-level status.
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadUserAccessDenied))
      << "Server shall return BadUserAccessDenied when Namespace policy denies Call";
  }
  else
  {
    // Service-level failure-the access-control denial may propagate as a service fault.
    // Either way, the status should indicate access denied.
    EXPECT_THAT(result, HasStatus(Status::BadUserAccessDenied))
      << "Server shall return BadUserAccessDenied at service or operation level";
  }
}

// Requirement: SVR-METH-CALL-047 (SHALL return)
// Bad_SecurityModeInsufficient - The security mode of the channel is insufficient.
// Spec: Part 4, section 5.11.2.4, line 4257
// @relation(SVR-METH-CALL-047, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_047_BadSecurityModeInsufficient)
{
  // EncryptionRequiredMethod has AccessRestrictions.EncryptionRequired.
  // Calling it on a None/None channel should return BadSecurityModeInsufficient.
  auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, mEncryptionRequiredMethodId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadSecurityModeInsufficient))
    << "Server shall return BadSecurityModeInsufficient when channel security is insufficient";
}

// Requirement: SVR-METH-CALL-048 (SHALL return)
// Bad_MethodInvalid - The method id does not refer to a Method for the specified Object.
// Spec: Part 4, section 5.11.2.4, line 4258
// @relation(SVR-METH-CALL-048, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_048_BadMethodInvalid)
{
  // Use the WritableVariable's NodeId as methodId - it exists but is not a Method.
  auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, mWritableVariableId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  // The spec requires BadMethodInvalid. The server may also return BadNodeClassInvalid
  // (the methodId resolves to a Variable, not a Method).
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadMethodInvalid))
    << "Server shall return BadMethodInvalid when methodId does not refer to a Method";
}

// Requirement: SVR-METH-CALL-048 (SHALL return)
// Method ID is valid but is NOT a component of the specified Object -> BadMethodInvalid.
// Spec: Part 4, section 5.11.2.4, line 4258
// @verifies CL-METH-002
// @relation(CL-METH-002, SVR-METH-CALL-048, scope=function)
// @verifies AC-SVR-ADDRSP-106-CALL-OBJECTID-IS-OWNER
TEST_F(ComplianceWithNodes, METH_CALL_048_MethodOnWrongObject)
{
  // TestMethod is a component of TestFolder. Call it with OtherObject as objectId.
  // OtherObject does NOT have HasComponent to TestMethod.
  auto result = mSession->methods().try_call_sync(
    call_method(mOtherObjectId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  // Spec requires BadMethodInvalid. SDK currently returns BadNodeIdInvalid (known gap).
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadMethodInvalid))
    << "Server shall return BadMethodInvalid when method is not a component of the object";
}

// Requirement: SVR-METH-CALL-050 (SHALL return)
// Bad_OutOfRange - Used to indicate that an input argument is outside the acceptable range.
// Spec: Part 4, section 5.11.2.4, line 4265
//
// Note: SVR-METH-CALL-050 is an input argument result code. It requires the server or handler
// to validate argument values against the Argument definition's range constraints (e.g.
// EURange, EngineeringUnits). The MethodAdapter does not perform range validation - it only
// validates types and counts. A faithful test requires a method with InputArguments that
// include range metadata, plus server-side range validation logic.
// This requirement is not testable with the current SDK infrastructure and is deferred.

// Requirement: SVR-METH-CALL-051 (SHALL return)
// Bad_TypeMismatch - Used to indicate that an input argument does not have the correct data type.
// Spec: Part 4, section 5.11.2.4, line 4267
//
// SVR-METH-CALL-051 is an input argument result code (Table 68). When an input argument has the
// wrong type, the operation-level statusCode should be BadInvalidArgument (SVR-METH-CALL-045,
// Table 67), with BadTypeMismatch in the corresponding inputArgumentResults entry.
// @verifies CL-METH-005, CL-METH-003
// @relation(CL-METH-003, CL-METH-005, SVR-METH-CALL-051, SVR-METH-CALL-061, scope=function)
// @relation(AC-SVR-METH-CALL-051-ARG-BAD-TYPEMISMATCH, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_051_BadTypeMismatch)
{
  // TestMethod expects 2 Int32 arguments. Provide a Double for the second.
  auto result = mSession->methods().try_call_sync(
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{double{2.5}}}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);

  // Operation-level: BadInvalidArgument (the wrapper code for argument validation failures).
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadInvalidArgument))
    << "Operation status should be BadInvalidArgument";

  // inputArgumentResults: the second argument should have BadTypeMismatch.
  ASSERT_GE(resp.results()[0].input_argument_results().size(), 2u);
  EXPECT_THAT(resp.results()[0].input_argument_results()[1], HasStatus(Status::BadTypeMismatch))
    << "Second argument should have BadTypeMismatch in inputArgumentResults";

  // Model-driven validation precedes a raw handler, rather than relying on an adapter's type check.
  auto addressSpace = mServer.server().address_space();
  auto methodNode = addressSpace.find_node_sync(mTestMethodId);
  const NodeId inputArgumentsId{mTestNamespaceIndex, uint32_t{3930}};
  auto inputNode = addressSpace.create_node_sync(inputArgumentsId, NodeClass::Variable);
  auto inputVariable = inputNode.as<VariableAccessor>();
  ASSERT_TRUE(inputVariable.has_value());
  inputVariable->set_browse_name(QualifiedName{0, "InputArguments"});
  inputVariable->set_display_name(LocalizedText{"", "InputArguments"});
  inputVariable->set_data_type(NodeId{DataTypeId::Argument});
  inputVariable->set_value_rank(ValueRank{1});
  Array<RefStructure<Structure>> arguments;
  for (std::string_view name : {"First", "Second"})
  {
    auto argument = std::make_unique<Argument>();
    argument->name() = String{name};
    argument->data_type() = NodeId{DataTypeId::Int32};
    argument->value_rank() = -1;
    arguments.push_back(RefStructure<Structure>{std::move(argument)});
  }
  inputVariable->write_value_sync(DataValue{Variant{std::move(arguments)}});
  inputNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
  methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, inputArgumentsId);

  auto invocations = std::make_shared<std::atomic<std::size_t>>(0);
  auto* callSource = mTestNamespace->find_node<Node>(mTestMethodId)->method_call_source();
  ASSERT_NE(callSource, nullptr);
  callSource->set_call_handler(
    [invocations](const CallMethodRequest&,
      std::shared_ptr<const MethodCallContext>,
      std::function<void(CallResult)>
        complete)
    {
      invocations->fetch_add(1);
      CallMethodResult answer;
      answer.output_arguments().push_back(Variant{int32_t{73}});
      complete(CallResult{std::move(answer)});
    });

  {
    auto control = mSession->methods().try_call_sync(
      call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(control, HasStatus(Status::Good));
    auto response = std::move(control).value();
    ASSERT_EQ(response.results().size(), 1u);
    ASSERT_THAT(response.results()[0], HasStatus(Status::Good));
    ASSERT_EQ(response.results()[0].output_arguments().size(), 1u);
    EXPECT_EQ(response.results()[0].output_arguments()[0], Variant{int32_t{73}});
    ASSERT_EQ(invocations->load(), 1u);
  }
  invocations->store(0);
  {
    auto refused = mSession->methods().try_call_sync(
      call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{String{"not an Int32"}}}));
    ASSERT_THAT(refused, HasStatus(Status::Good));
    auto response = std::move(refused).value();
    ASSERT_EQ(response.results().size(), 1u);
    EXPECT_THAT(response.results()[0], HasStatus(Status::BadInvalidArgument));
    ASSERT_EQ(response.results()[0].input_argument_results().size(), 2u);
    EXPECT_THAT(response.results()[0].input_argument_results()[0], HasStatus(Status::Good));
    EXPECT_THAT(response.results()[0].input_argument_results()[1], HasStatus(Status::BadTypeMismatch));
    EXPECT_TRUE(response.results()[0].output_arguments().empty());
    EXPECT_EQ(invocations->load(), 0u) << "a String for the declared Int32 must not reach the handler";
  }
}

// Part 4 section 5.11.2.4 Table 68: ByteString is accepted for a one-dimensional Byte array.
// @relation(AC-SVR-METH-CALL-032-BYTESTRING-FOR-BYTE-ARRAY, scope=function)
// @relation(AC-SVR-METH-CALL-051-ARG-BAD-TYPEMISMATCH, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_032_ByteStringForByteArrayIsAccepted)
{
  auto addressSpace = mServer.server().address_space();
  const NodeId methodId{mTestNamespaceIndex, uint32_t{3910}};
  auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "AcceptByteStringPayload"});
  method->set_display_name(LocalizedText{"", "AcceptByteStringPayload"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);
  methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, false);

  uint32_t propertyIdentifier{3911};
  for (const bool input : {true, false})
  {
    std::string_view propertyName{"InputArguments"};
    DataTypeId dataType{DataTypeId::Byte};
    int32_t valueRank{1};
    if (!input)
    {
      propertyName = "OutputArguments";
      dataType = DataTypeId::UInt32;
      valueRank = -1;
    }
    const NodeId propertyId{mTestNamespaceIndex, propertyIdentifier++};
    auto propertyNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto property = propertyNode.as<VariableAccessor>();
    ASSERT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, propertyName});
    property->set_display_name(LocalizedText{"", propertyName});
    property->set_data_type(NodeId{DataTypeId::Argument});
    property->set_value_rank(ValueRank{1});
    auto argument = std::make_unique<Argument>();
    argument->name() = String{propertyName};
    argument->data_type() = NodeId{dataType};
    argument->value_rank() = valueRank;
    if (input)
    {
      argument->array_dimensions().push_back(0);
    }
    Array<RefStructure<Structure>> arguments;
    arguments.push_back(RefStructure<Structure>{std::move(argument)});
    property->write_value_sync(DataValue{Variant{std::move(arguments)}});
    propertyNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
  }

  auto invocations = std::make_shared<std::atomic<std::size_t>>(0);
  auto receivedRequest = std::make_shared<std::promise<CallMethodRequest>>();
  auto received = receivedRequest->get_future();
  auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
  ASSERT_NE(callSource, nullptr);
  callSource->set_call_handler(
    [invocations, receivedRequest](const CallMethodRequest& request,
      std::shared_ptr<const MethodCallContext>,
      std::function<void(CallResult)>
        complete)
    {
      if (invocations->fetch_add(1) == 0)
      {
        receivedRequest->set_value(request);
      }
      CallMethodResult answer;
      answer.output_arguments().push_back(Variant{uint32_t{0xB6C032}});
      complete(CallResult{std::move(answer)});
    });

  const ByteString payload{
    std::vector<uint8_t>{0x42, 0x36, 0x63, 0x2d, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64}};
  auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, methodId, {Variant{payload}}));
  ASSERT_THAT(result, HasStatus(Status::Good));
  auto response = std::move(result).value();
  EXPECT_THAT(response, ServiceResultIs(StatusCode{Status::Good}));
  ASSERT_EQ(response.results().size(), 1u);
  ASSERT_THAT(response.results()[0], HasStatus(Status::Good));
  EXPECT_TRUE(response.results()[0].input_argument_results().empty());
  ASSERT_EQ(response.results()[0].output_arguments().size(), 1u);
  EXPECT_EQ(response.results()[0].output_arguments()[0], Variant{uint32_t{0xB6C032}});
  EXPECT_EQ(invocations->load(), 1u);
  ASSERT_EQ(received.wait_for(std::chrono::seconds{0}), std::future_status::ready);
  const auto actual = received.get();
  EXPECT_EQ(actual.object_id(), mTestFolderId);
  EXPECT_EQ(actual.method_id(), methodId);
  ASSERT_EQ(actual.input_arguments().size(), 1u);
  const auto* actualPayload = actual.input_arguments()[0].try_as<ByteString>();
  ASSERT_NE(actualPayload, nullptr);
  EXPECT_EQ(*actualPayload, payload);
}

// Part 3 section 8.6 and Part 4 section 5.11.2.4: String is not the ByteString/Byte-array exception.
// @relation(AC-SVR-METH-CALL-051-ARG-BAD-TYPEMISMATCH, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_051_StringForByteArrayIsRefused)
{
  auto addressSpace = mServer.server().address_space();
  const NodeId methodId{mTestNamespaceIndex, uint32_t{3920}};
  auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "ByteArrayTypeContrast"});
  method->set_display_name(LocalizedText{"", "ByteArrayTypeContrast"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);
  methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{mTestFolderId}, false);

  uint32_t propertyIdentifier{3921};
  for (const bool input : {true, false})
  {
    std::string_view propertyName{"InputArguments"};
    DataTypeId dataType{DataTypeId::Byte};
    int32_t valueRank{1};
    if (!input)
    {
      propertyName = "OutputArguments";
      dataType = DataTypeId::UInt32;
      valueRank = -1;
    }
    const NodeId propertyId{mTestNamespaceIndex, propertyIdentifier++};
    auto propertyNode = addressSpace.create_node_sync(propertyId, NodeClass::Variable);
    auto property = propertyNode.as<VariableAccessor>();
    ASSERT_TRUE(property.has_value());
    property->set_browse_name(QualifiedName{0, propertyName});
    property->set_display_name(LocalizedText{"", propertyName});
    property->set_data_type(NodeId{DataTypeId::Argument});
    property->set_value_rank(ValueRank{1});
    auto argument = std::make_unique<Argument>();
    argument->name() = String{propertyName};
    argument->data_type() = NodeId{dataType};
    argument->value_rank() = valueRank;
    if (input)
    {
      argument->array_dimensions().push_back(0);
    }
    Array<RefStructure<Structure>> arguments;
    arguments.push_back(RefStructure<Structure>{std::move(argument)});
    property->write_value_sync(DataValue{Variant{std::move(arguments)}});
    propertyNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
    methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, propertyId);
  }

  auto invocations = std::make_shared<std::atomic<std::size_t>>(0);
  auto receivedRequest = std::make_shared<std::promise<CallMethodRequest>>();
  auto received = receivedRequest->get_future();
  auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
  ASSERT_NE(callSource, nullptr);
  callSource->set_call_handler(
    [invocations, receivedRequest](const CallMethodRequest& request,
      std::shared_ptr<const MethodCallContext>,
      std::function<void(CallResult)>
        complete)
    {
      if (invocations->fetch_add(1) == 0)
      {
        receivedRequest->set_value(request);
      }
      CallMethodResult answer;
      answer.output_arguments().push_back(Variant{uint32_t{0xB6C051}});
      complete(CallResult{std::move(answer)});
    });

  const ByteString payload{
    std::vector<uint8_t>{0x42, 0x36, 0x63, 0x2d, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64}};
  auto control = mSession->methods().try_call_sync(call_method(mTestFolderId, methodId, {Variant{payload}}));
  ASSERT_THAT(control, HasStatus(Status::Good));
  auto response = std::move(control).value();
  EXPECT_THAT(response, ServiceResultIs(StatusCode{Status::Good}));
  ASSERT_EQ(response.results().size(), 1u);
  ASSERT_THAT(response.results()[0], HasStatus(Status::Good));
  EXPECT_TRUE(response.results()[0].input_argument_results().empty());
  ASSERT_EQ(response.results()[0].output_arguments().size(), 1u);
  EXPECT_EQ(response.results()[0].output_arguments()[0], Variant{uint32_t{0xB6C051}});
  EXPECT_EQ(invocations->load(), 1u);
  ASSERT_EQ(received.wait_for(std::chrono::seconds{0}), std::future_status::ready);
  const auto actual = received.get();
  EXPECT_EQ(actual.object_id(), mTestFolderId);
  EXPECT_EQ(actual.method_id(), methodId);
  ASSERT_EQ(actual.input_arguments().size(), 1u);
  const auto* actualPayload = actual.input_arguments()[0].try_as<ByteString>();
  ASSERT_NE(actualPayload, nullptr);
  EXPECT_EQ(*actualPayload, payload);

  // The same installed handler is reachable for ByteString, but must not receive String.
  const auto callsBeforeRefusal = invocations->load();
  ASSERT_EQ(callsBeforeRefusal, 1u);
  {
    auto refused = mSession->methods().try_call_sync(
      call_method(mTestFolderId, methodId, {Variant{String{"B6c-payload"}}}));
    ASSERT_THAT(refused, HasStatus(Status::Good));
    auto refusedResponse = std::move(refused).value();
    EXPECT_THAT(refusedResponse, ServiceResultIs(StatusCode{Status::Good}));
    ASSERT_EQ(refusedResponse.results().size(), 1u);
    EXPECT_THAT(refusedResponse.results()[0], HasStatus(Status::BadInvalidArgument));
    ASSERT_EQ(refusedResponse.results()[0].input_argument_results().size(), 1u);
    EXPECT_THAT(refusedResponse.results()[0].input_argument_results()[0], HasStatus(Status::BadTypeMismatch));
    EXPECT_TRUE(refusedResponse.results()[0].output_arguments().empty());
    EXPECT_EQ(invocations->load() - callsBeforeRefusal, 0u)
      << "String must be refused before the installed handler executes";
  }
}

// Requirement: SVR-METH-CALL-060 (SHALL return)
// Bad_NothingToDo - The methodsToCall list was empty.
// Spec: Part 4, section 5.11.2.3, line 4226
// @relation(SVR-METH-CALL-060, SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_060_BadNothingToDo)
{
  // Send an empty Call request.
  CallRequest req;
  // methods_to_call is empty by default.

  auto result = mSession->methods().try_call_sync(std::move(req));
  // This should be a service-level error.
  ASSERT_TRUE(result.is_bad()) << "Empty Call request should fail at service level";
  EXPECT_THAT(result, HasStatus(Status::BadNothingToDo))
    << "Server shall return BadNothingToDo for empty methodsToCall list";
}

// Requirement: SVR-METH-CALL-061 (SHALL return)
// Bad_TooManyOperations - Too many operations were requested.
// Spec: Part 4, section 5.11.2.3, line 4227
// @relation(SVR-METH-CALL-061, scope=function)
TEST_F(ComplianceMethodOpLimited, METH_CALL_061_BadTooManyOperations)
{
  // MaxNodesPerMethodCall is set to 1. Send 2 method calls.
  auto result = mSession->methods().try_call_sync(
    CallRequestBuilder().call(mObjectId, mMethodId).call(mObjectId, mMethodId));
  ASSERT_TRUE(result.is_bad()) << "Should fail at service level";
  EXPECT_THAT(result, HasStatus(Status::BadTooManyOperations))
    << "Server shall return BadTooManyOperations when exceeding MaxNodesPerMethodCall";
}

// ===========================================================================
// Obligation tests: the refusal half of the objectId/methodId pairing rules
// ===========================================================================

// Part 4 section 5.11.2.2 - `objectId` is the Method's invocation context and may only name an Object or an
// ObjectType; every other NodeClass has no HasComponent path that could be checked. An implementation
// that resolves `objectId` only to prove the Node exists, then goes straight to the Method's own
// Executable/handler, executes the Method against a Variable, a Method or a DataType as though it were
// a valid context.
// @verifies AC-SVR-METH-CALL-010-OBJECTID-IS-OBJECT-OR-TYPE
TEST_F(ComplianceWithNodes, METH_CALL_010_NonObjectNodeClassAsObjectIdIsRefused)
{
  // The criterion's OBSERVATION is "It is refused", and SVR-METH-CALL-010 names the two codes that
  // discharge it: "Any other NodeClass (Variable, Method, ReferenceType, DataType, etc.) is rejected
  // per SVR-METH-CALL-040 (Bad_NodeIdInvalid) or SVR-METH-CALL-048 (Bad_MethodInvalid)." Both are
  // asserted as a disjunction rather than picking one, so the test states the obligation and not an
  // implementation's choice between the two - while still failing an implementation that accepts the
  // pairing, or that refuses it with an unrelated code.
  const auto expectRefused = [](const CallMethodResult& result, const char* what)
  {
    const auto status = result.status_code();
    EXPECT_TRUE(status.is_bad()) << what;
    EXPECT_TRUE(status == Status::BadNodeIdInvalid || status == Status::BadMethodInvalid)
      << what << " - SVR-METH-CALL-010 admits Bad_NodeIdInvalid or Bad_MethodInvalid; got "
      << status.as_uint32();
  };

  // Control: the same methodId with its owning Object is accepted and executes, so the refusals below
  // cannot be a blanket failure of the Call path.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: an Object as objectId is accepted";
  }

  // A Variable NodeId as objectId.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(mWritableVariableId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    expectRefused(resp.results()[0],
      "a Variable is neither an Object nor an ObjectType and must not be accepted as objectId");
  }

  // A Method NodeId as objectId.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(mTestMethodId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    expectRefused(resp.results()[0],
      "a Method is neither an Object nor an ObjectType and must not be accepted as objectId");
  }

  // A DataType NodeId (NS0 Int32) as objectId.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(NodeId{DataTypeId::Int32}, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    expectRefused(resp.results()[0],
      "a DataType is neither an Object nor an ObjectType and must not be accepted as objectId");
  }

  // A ReferenceType NodeId (NS0 HasComponent) as objectId.
  {
    auto result = mSession->methods().try_call_sync(call_method(
      NodeId{ReferenceTypeId::HasComponent}, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    expectRefused(resp.results()[0],
      "a ReferenceType is neither an Object nor an ObjectType and must not be accepted as objectId");
  }
}

// Part 4 section 5.11.2.2 - when `objectId` names an ObjectType, that type OR one of its supertypes must
// source a HasComponent reference to `methodId`. The rule cuts both ways: an implementation that checks only
// the named type refuses every inherited Method, while one that skips the topology check altogether accepts
// any (ObjectType, Method) pair. This drives both halves against a real supertype chain - the control
// proves the chain is walked, the obligation proves an unowned Method is still refused.
// @verifies AC-SVR-METH-CALL-011-OBJECTTYPE-COMPONENT-SOURCE
TEST_F(ComplianceWithNodes, METH_CALL_011_ObjectTypeWithoutComponentInChainIsRefused)
{
  auto addressSpace = mServer.server().address_space();

  // SubTestObjectType: a genuine subtype of TestObjectType (inverse HasSubtype names the supertype).
  // TestObjectType sources HasComponent -> ObjectTypeMethod; the subtype sources nothing itself.
  const NodeId subTypeId{mTestNamespaceIndex, uint32_t{7100}};
  auto subTypeNode = addressSpace.create_node_sync(subTypeId, NodeClass::ObjectType);
  auto subType = subTypeNode.as<ObjectTypeAccessor>();
  ASSERT_TRUE(subType.has_value());
  subType->set_browse_name(QualifiedName{mTestNamespaceIndex, "SubTestObjectType"});
  subType->set_display_name(LocalizedText{"", "SubTestObjectType"});
  subType->set_is_abstract(false);
  subTypeNode.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, mTestObjectTypeId, /*isForward=*/false);

  // Control: the Method is sourced by the SUPERTYPE only, so accepting it proves the supertype chain is
  // actually walked (and that the refusal below is about topology, not about subtypes generally).
  {
    auto result = mSession->methods().try_call_sync(call_method(subTypeId, mObjectTypeMethodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good())
      << "control: a Method sourced by a supertype must resolve for the subtype";
  }

  // Obligation: TestMethod is sourced by TestFolder (an Object). Neither SubTestObjectType nor its
  // supertype TestObjectType sources it, so the pairing has no HasComponent path.
  {
    auto result = mSession->methods().try_call_sync(call_method(subTypeId, mTestMethodId));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    // AC-SVR-METH-CALL-011's OBSERVATION is "It is refused"; the refusal CODE is a separate
    // obligation carried by AC-SVR-METH-CALL-048, so the refusal alone is what is asserted here.
    // (This SDK answers Bad_NodeIdInvalid rather than Bad_MethodInvalid whenever the objectId was
    // itself a type Node - a deliberate branch citing OPC 10000-9 5.5.6/5.7.3/5.7.4, which requires
    // Bad_NodeIdInvalid for a Condition Method invoked with the ConditionType Node.)
    EXPECT_TRUE(resp.results()[0].status_code().is_bad())
      << "an ObjectType that neither it nor any supertype sources the Method from must be refused";
  }
}

// Part 4 section 5.11.2.2 - when `objectId` names an Object, the Method must be sourced by the Object itself,
// by its ObjectType, or by a supertype of that ObjectType. An implementation that stops at the instance's own
// references refuses every type-declared Method; one that stops at the type definition and never climbs
// refuses inherited ones; one that omits the check entirely runs any Method against any Object. The
// control exercises the full instance -> type -> supertype climb; the obligation is the refusal when no
// link in that chain sources the Method.
// @verifies AC-SVR-METH-CALL-012-OBJECT-COMPONENT-SOURCE
TEST_F(ComplianceWithNodes, METH_CALL_012_ObjectWithoutComponentInTypeChainIsRefused)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId subTypeId{mTestNamespaceIndex, uint32_t{7110}};
  auto subTypeNode = addressSpace.create_node_sync(subTypeId, NodeClass::ObjectType);
  auto subType = subTypeNode.as<ObjectTypeAccessor>();
  ASSERT_TRUE(subType.has_value());
  subType->set_browse_name(QualifiedName{mTestNamespaceIndex, "SubTypedInstanceType"});
  subType->set_display_name(LocalizedText{"", "SubTypedInstanceType"});
  subType->set_is_abstract(false);
  subTypeNode.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, mTestObjectTypeId, /*isForward=*/false);

  // An instance of that subtype. It sources no Method of its own; ObjectTypeMethod is two hops away
  // (HasTypeDefinition -> SubTypedInstanceType, HasSubtype -> TestObjectType, HasComponent -> Method).
  const NodeId instanceId{mTestNamespaceIndex, uint32_t{7111}};
  auto instanceNode = addressSpace.create_node_sync(instanceId, NodeClass::Object);
  auto instance = instanceNode.as<ObjectAccessor>();
  ASSERT_TRUE(instance.has_value());
  instance->set_browse_name(QualifiedName{mTestNamespaceIndex, "SubTypedObject"});
  instance->set_display_name(LocalizedText{"", "SubTypedObject"});
  instanceNode.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, subTypeId);
  addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder})
    .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, instanceId);

  // Control: the Method is reachable only through the instance's type chain.
  {
    auto result = mSession->methods().try_call_sync(call_method(instanceId, mObjectTypeMethodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good())
      << "control: a Method sourced by the Object's type chain must resolve for the instance";
  }

  // Obligation: TestMethod is sourced by TestFolder only - not by the instance, not by its ObjectType,
  // not by that type's supertype.
  {
    auto result = mSession->methods().try_call_sync(call_method(instanceId, mTestMethodId));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadMethodInvalid))
      << "an Object whose own references and whole type chain lack the Method must be refused";
  }
}

// Part 4 section 5.11.2.2 - "The list shall be empty if the statusCode Severity is Bad." The obligation is on
// the response framer, not on the Method: a handler is free to compute partial outputs and then fail, and the
// server must still serialize an empty outputArguments. An implementation that simply forwards whatever
// CallMethodResult the handler produced hands the Client partial values beside a Bad code - values a
// Client has every reason to read, and the most convincing kind of wrong answer.
// @relation(AC-SVR-METH-CALL-021-BAD-MEANS-NO-OUTPUTS, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_021_HandlerOutputsDroppedWhenStatusIsBad)
{
  auto addressSpace = mServer.server().address_space();

  const NodeId failingMethodId{mTestNamespaceIndex, uint32_t{3500}};
  auto methodNode = addressSpace.create_node_sync(failingMethodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "FailsWithOutputsMethod"});
  method->set_display_name(LocalizedText{"", "FailsWithOutputsMethod"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, failingMethodId);

  // The Method body fails AFTER computing two output values - the case the obligation is written for.
  {
    auto* callSource = mTestNamespace->find_node<Node>(failingMethodId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [](const CallMethodRequest&,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        CallMethodResult r;
        r.status_code() = Status::BadInternalError;
        r.output_arguments().resize(2);
        r.output_arguments()[0] = Variant{int32_t{111}};
        r.output_arguments()[1] = Variant{int32_t{222}};
        cb(CallResult{std::move(r)});
      });
  }

  auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, failingMethodId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  // Asserting the handler's own code proves the body ran and really did populate the outputs, so the
  // emptiness below cannot pass because the Call was refused before reaching the Method.
  ASSERT_THAT(resp.results()[0], HasStatus(Status::BadInternalError))
    << "the handler's Bad status must reach the Client";
  EXPECT_TRUE(resp.results()[0].output_arguments().empty())
    << "outputArguments shall be empty when the statusCode Severity is Bad, whatever the Method returned";
}

// Part 4 section 5.11.2.2 - "The list shall be empty if the statusCode Severity is Bad." The obligation is
// per-operation: one Call request carries many CallMethodResults, and the emptying is decided from each
// result's own severity. Two plausible implementations get this wrong in opposite directions - one that
// forwards each handler's CallMethodResult untouched leaks the failed Method's partial outputs, and one
// that reacts to "the request contained a failure" by clearing the whole results array destroys the
// outputs of the operations that actually succeeded. This drives a failing and a succeeding Method in a
// single request so that both halves are observed against each other.
// @verifies AC-SVR-METH-CALL-021-BAD-MEANS-NO-OUTPUTS
TEST_F(ComplianceWithNodes, METH_CALL_021_BadResultCarriesNoOutputArgumentsPerOperation)
{
  auto addressSpace = mServer.server().address_space();

  // A Method whose body computes two outputs and then fails - the case the obligation is written for.
  const NodeId failingMethodId{mTestNamespaceIndex, uint32_t{3520}};
  auto methodNode = addressSpace.create_node_sync(failingMethodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "FailsBesideASiblingMethod"});
  method->set_display_name(LocalizedText{"", "FailsBesideASiblingMethod"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, failingMethodId);

  {
    auto* callSource = mTestNamespace->find_node<Node>(failingMethodId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [](const CallMethodRequest&,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        CallMethodResult r;
        r.status_code() = Status::BadInternalError;
        r.output_arguments().resize(2);
        r.output_arguments()[0] = Variant{int32_t{777}};
        r.output_arguments()[1] = Variant{int32_t{888}};
        cb(CallResult{std::move(r)});
      });
  }

  // Operation 0 fails with outputs populated; operation 1 is the Add Method and must keep its output.
  auto result = mSession->methods().try_call_sync(
    CallRequestBuilder()
      .call(mTestFolderId, failingMethodId)
      .call(mTestFolderId, mTestMethodId, {Variant{int32_t{20}}, Variant{int32_t{22}}}));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);

  // The handler's own code proves the body ran and really did populate outputs, so the emptiness below
  // cannot pass because the operation was refused before the Method was reached.
  ASSERT_THAT(resp.results()[0], HasStatus(Status::BadInternalError))
    << "the handler's Bad status must reach the Client as that operation's result";
  EXPECT_TRUE(resp.results()[0].output_arguments().empty())
    << "outputArguments shall be empty for the operation whose statusCode Severity is Bad";

  // The sibling fixes what the emptying means: it is keyed on the failed operation's own severity, not
  // on the request as a whole.
  ASSERT_THAT(resp.results()[1], Good())
    << "the succeeding operation shall not be affected by its sibling's failure";
  ASSERT_EQ(resp.results()[1].output_arguments().size(), 1u)
    << "a Good operation shall keep the outputArguments its Method computed";
  EXPECT_EQ(resp.results()[1].output_arguments()[0].as<int32_t>(), 42);
}

// Part 4 section 5.11.2.4 - Bad_NodeIdInvalid is the code for an `objectId` whose syntax is not valid,
// against Bad_NodeIdUnknown for one that is well formed but names nothing. A null NodeId is the degenerate
// malformed case; an implementation that hands every objectId straight to the address space gets a
// "not found" answer back and reports Unknown, collapsing a distinction the Client uses to tell a bad
// request from a stale one. (The SDK's Read, HistoryRead and DeleteNodes surfaces already map null ->
// Bad_NodeIdInvalid.)
// @relation(AC-SVR-METH-CALL-040-BAD-NODEIDINVALID, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_040_NullObjectIdIsBadNodeIdInvalid)
{
  auto result = mSession->methods().try_call_sync(call_method(NodeId{}, mTestMethodId));
  ASSERT_THAT(result, Good()) << "Service-level should succeed";
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdInvalid))
    << "a null (syntactically invalid) objectId shall return BadNodeIdInvalid, not BadNodeIdUnknown";
}

// Part 4 section 5.11.2.4 - Bad_NodeIdInvalid is the per-operation answer to a syntactically invalid
// `objectId`, while Bad_NodeIdUnknown is reserved for one that is well formed and names nothing. OPC 10000-6
// section 5.2.2.9 gives the null NodeId several encodings - numeric zero, an empty String, and the default -
// and every one of them is the same malformed objectId. Two implementations fail here: one that never screens
// the objectId at all reports Unknown for all of them, and one patched with a bare `objectId == NodeId{}`
// comparison answers Invalid for the numeric form only and still reports Unknown for `ns=0;s=`, which is
// the identical request on the wire. The valid sibling operation in each request pins the refusal to that
// operation rather than to the Call service.
// @relation(AC-SVR-METH-CALL-040-BAD-NODEIDINVALID, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_040_SyntacticallyInvalidObjectIdIsBadNodeIdInvalidPerOperation)
{
  const auto expectRefusedAsInvalid = [this](const NodeId& malformedObjectId, const char* what)
  {
    ASSERT_TRUE(malformedObjectId.is_null())
      << what << " - the encoding must itself be a null (malformed) NodeId";

    // Operation 0 is a valid call; operation 1 carries the malformed objectId.
    auto result = mSession->methods().try_call_sync(
      CallRequestBuilder()
        .call(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}})
        .call(malformedObjectId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good()) << what << " - the Call service itself shall succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 2u);
    ASSERT_THAT(resp.results()[0], Good())
      << what << " - control: the valid operation beside it shall still succeed";
    EXPECT_THAT(resp.results()[1], HasStatus(Status::BadNodeIdInvalid))
      << what
      << " - a syntactically invalid objectId shall be Bad_NodeIdInvalid for that operation, "
         "not Bad_NodeIdUnknown";
  };

  expectRefusedAsInvalid(NodeId{}, "a default-constructed null objectId");
  expectRefusedAsInvalid(NodeId{uint16_t{0}, uint32_t{0}}, "the ns=0;i=0 null encoding as objectId");
  expectRefusedAsInvalid(NodeId{uint16_t{0}, String{""}}, "the ns=0;s= null encoding as objectId");
}

// The CTT's Method Call Err-001 pairs the null objectId with a Method its Session may not call. A null
// objectId is invalid by syntax alone, so the answer is Bad_NodeIdInvalid whatever the Method's
// permissions; authorising the Method first answered Bad_UserAccessDenied for a request that names no
// object at all. ServerConfiguration.UpdateCertificate stands in for that Method: the NodeSet restricts
// it to security administrators, which this fixture's anonymous Session is not.
// @relation(AC-SVR-METH-CALL-040-BAD-NODEIDINVALID, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_040_NullObjectIdIsBadNodeIdInvalidEvenForAMethodTheSessionMayNotCall)
{
  auto result = mSession->methods().try_call_sync(
    CallRequestBuilder()
      .call(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}})
      .call(NodeId{uint16_t{0}, uint32_t{0}}, NodeId{MethodId::ServerConfiguration_UpdateCertificate}, {}));
  ASSERT_THAT(result, Good());
  auto resp = std::move(result).value();
  ASSERT_EQ(resp.results().size(), 2u);
  ASSERT_THAT(resp.results()[0], Good()) << "control: the valid operation beside it shall still succeed";
  EXPECT_THAT(resp.results()[1], HasStatus(Status::BadNodeIdInvalid));
}

// Part 4 section 5.11.2.4 - Executable is state, not permission: a Method the machine currently forbids. The
// obligation has two halves, and the second is the one that matters. An implementation that invokes the
// handler and then overwrites the result with Bad_NotExecutable reports the right code while the Method
// body has already run - side effects and all. The Executable gate must be evaluated BEFORE dispatch.
// @verifies AC-SVR-METH-CALL-042-BAD-NOTEXECUTABLE
TEST_F(ComplianceWithNodes, METH_CALL_042_NonExecutableMethodIsRefusedAndBodyDoesNotRun)
{
  auto addressSpace = mServer.server().address_space();
  auto folderNode = addressSpace.find_node_sync(mTestFolderId);

  auto blockedRan = std::make_shared<std::atomic<bool>>(false);
  auto controlRan = std::make_shared<std::atomic<bool>>(false);

  // Two Methods on TestFolder that differ ONLY in Executable. Each body records that it ran.
  const auto createProbeMethod =
    [&](uint32_t identifier, std::string browseName, bool executable, std::shared_ptr<std::atomic<bool>> ran)
  {
    const NodeId methodId{mTestNamespaceIndex, identifier};
    auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    EXPECT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{mTestNamespaceIndex, browseName});
    method->set_display_name(LocalizedText{"", browseName});
    method->set_executable(executable);
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

    auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
    EXPECT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [ran](const CallMethodRequest&,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        ran->store(true);
        CallMethodResult r;
        cb(CallResult{std::move(r)});
      });
    return methodId;
  };

  const NodeId blockedMethodId =
    createProbeMethod(uint32_t{3510}, "ExecutableFalseProbeMethod", false, blockedRan);
  const NodeId controlMethodId =
    createProbeMethod(uint32_t{3511}, "ExecutableTrueProbeMethod", true, controlRan);

  // Control first: the identical probe with Executable = TRUE runs, so "did not run" below is a real
  // observation of the body rather than a handler that was never reachable.
  {
    auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, controlMethodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: an executable probe Method succeeds";
    ASSERT_TRUE(controlRan->load()) << "control: the probe body records its own invocation";
  }

  {
    auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, blockedMethodId));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNotExecutable))
      << "Server shall return BadNotExecutable when the Executable Attribute is FALSE";
    EXPECT_FALSE(blockedRan->load())
      << "the Method body shall not run when the Executable Attribute is FALSE";
  }
}

// ===========================================================================
// Obligation tests: argument-arity refusals must precede dispatch
//
// Both of the arity criteria are conjunctions - the code AND the Method not
// running - so each test needs a Method whose declared InputArguments the
// SERVER can see (an InputArguments Property, which drives
// MethodServiceSet::validate_input_arguments) and whose body records its own
// invocation. A raw (non-adapter) handler is used deliberately: an adapter
// would do the arity check itself, and the obligation is on the server.
// ===========================================================================

// Part 4 section 5.11.2.4 - Bad_ArgumentsMissing when the Client omits a non-optional input, and
// SVR-METH-CALL-043 puts the refusal "without invoking the Method". Both halves matter: an
// implementation that zero-fills the missing slot and dispatches anyway runs the Method with a value
// the caller never chose, and one that dispatches first and overwrites the outcome afterwards reports
// the right code with the side effects already committed.
// @verifies AC-SVR-METH-CALL-043-BAD-ARGUMENTSMISSING
TEST_F(ComplianceWithNodes, METH_CALL_043_MissingRequiredArgumentIsRefusedAndMethodDoesNotRun)
{
  auto addressSpace = mServer.server().address_space();

  auto ran = std::make_shared<std::atomic<bool>>(false);
  auto seenArgumentCount = std::make_shared<std::atomic<size_t>>(0);

  // A Method declaring exactly two REQUIRED Int32 inputs, in the model rather than in a handler
  // wrapper, so the server's own model-driven validation is the thing under test.
  const NodeId methodId{mTestNamespaceIndex, uint32_t{3600}};
  auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "TwoRequiredArgsMethod"});
  method->set_display_name(LocalizedText{"", "TwoRequiredArgsMethod"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

  const NodeId inputArgumentsId{mTestNamespaceIndex, uint32_t{3601}};
  auto inputNode = addressSpace.create_node_sync(inputArgumentsId, NodeClass::Variable);
  auto inputVariable = inputNode.as<VariableAccessor>();
  ASSERT_TRUE(inputVariable.has_value());
  inputVariable->set_browse_name(QualifiedName{0, "InputArguments"});
  inputVariable->set_display_name(LocalizedText{"", "InputArguments"});
  inputVariable->set_data_type(NodeId{DataTypeId::Argument});
  inputVariable->set_value_rank(ValueRank{1});
  {
    Array<RefStructure<Structure>> arguments;
    for (std::string_view name : {"First", "Second"})
    {
      auto argument = std::make_unique<Argument>();
      argument->name() = String{name};
      argument->data_type() = NodeId{DataTypeId::Int32};
      argument->value_rank() = -1;
      arguments.push_back(RefStructure<Structure>{std::move(argument)});
    }
    inputVariable->write_value_sync(DataValue{Variant{std::move(arguments)}});
  }
  methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, inputArgumentsId);

  {
    auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [ran, seenArgumentCount](const CallMethodRequest& request,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        ran->store(true);
        seenArgumentCount->store(request.input_arguments().size());
        CallMethodResult r;
        cb(CallResult{std::move(r)});
      });
  }

  // Control: the full argument list dispatches and the body records its own invocation, so
  // "did not run" below is an observation of the body and not of an unreachable handler.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(mTestFolderId, methodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: two declared arguments is a valid call";
    ASSERT_TRUE(ran->load()) << "control: the probe body records its own invocation";
    ASSERT_EQ(seenArgumentCount->load(), 2u) << "control: the body sees both supplied arguments";
  }

  ran->store(false);
  seenArgumentCount->store(0);

  {
    auto result =
      mSession->methods().try_call_sync(call_method(mTestFolderId, methodId, {Variant{int32_t{1}}}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadArgumentsMissing))
      << "omitting a non-optional input argument shall return Bad_ArgumentsMissing";
    EXPECT_FALSE(ran->load())
      << "the Method shall not be invoked when a non-optional input argument is missing";
    EXPECT_EQ(seenArgumentCount->load(), 0u)
      << "the Method shall not run with a defaulted value for the omitted argument";
  }
}

// Part 4 section 5.11.2.4 - Bad_TooManyArguments when the Client supplies more inputs than the Method
// declares, and SVR-METH-CALL-044 puts the refusal "without invoking the Method". Silently truncating
// the list to the declared arity is the dangerous reading: a Client built against a newer revision of
// the Method would have its trailing argument discarded and be told the call succeeded.
// @verifies AC-SVR-METH-CALL-044-BAD-TOOMANYARGUMENTS
TEST_F(ComplianceWithNodes, METH_CALL_044_ExtraArgumentIsRefusedAndMethodDoesNotRun)
{
  auto addressSpace = mServer.server().address_space();

  auto ran = std::make_shared<std::atomic<bool>>(false);
  auto seenArgumentCount = std::make_shared<std::atomic<size_t>>(0);

  const NodeId methodId{mTestNamespaceIndex, uint32_t{3610}};
  auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "ExactlyTwoArgsMethod"});
  method->set_display_name(LocalizedText{"", "ExactlyTwoArgsMethod"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

  const NodeId inputArgumentsId{mTestNamespaceIndex, uint32_t{3611}};
  auto inputNode = addressSpace.create_node_sync(inputArgumentsId, NodeClass::Variable);
  auto inputVariable = inputNode.as<VariableAccessor>();
  ASSERT_TRUE(inputVariable.has_value());
  inputVariable->set_browse_name(QualifiedName{0, "InputArguments"});
  inputVariable->set_display_name(LocalizedText{"", "InputArguments"});
  inputVariable->set_data_type(NodeId{DataTypeId::Argument});
  inputVariable->set_value_rank(ValueRank{1});
  {
    Array<RefStructure<Structure>> arguments;
    for (std::string_view name : {"First", "Second"})
    {
      auto argument = std::make_unique<Argument>();
      argument->name() = String{name};
      argument->data_type() = NodeId{DataTypeId::Int32};
      argument->value_rank() = -1;
      arguments.push_back(RefStructure<Structure>{std::move(argument)});
    }
    inputVariable->write_value_sync(DataValue{Variant{std::move(arguments)}});
  }
  methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, inputArgumentsId);

  {
    auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [ran, seenArgumentCount](const CallMethodRequest& request,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        ran->store(true);
        seenArgumentCount->store(request.input_arguments().size());
        CallMethodResult r;
        cb(CallResult{std::move(r)});
      });
  }

  // Control: the declared arity dispatches, so the refusal below is about the extra argument.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(mTestFolderId, methodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: exactly two arguments is a valid call";
    ASSERT_TRUE(ran->load()) << "control: the probe body records its own invocation";
  }

  ran->store(false);
  seenArgumentCount->store(0);

  {
    auto result = mSession->methods().try_call_sync(
      call_method(mTestFolderId, methodId, {Variant{int32_t{1}}, Variant{int32_t{2}}, Variant{int32_t{3}}}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadTooManyArguments))
      << "supplying more input arguments than declared shall return Bad_TooManyArguments";
    // The other half of "the extra is not ignored": the Method must not have been dispatched with a
    // truncated argument list.
    EXPECT_FALSE(ran->load()) << "the Method shall not be invoked when too many arguments are supplied";
    EXPECT_EQ(seenArgumentCount->load(), 0u)
      << "the extra argument shall not be silently dropped and the Method run with the rest";
  }
}

// ===========================================================================
// Fixture: ComplianceMethodPerUserAuthz - two sessions differing ONLY in the
// authenticated principal, and Namespace Call policy keyed on
// that principal.
//
// The authenticator stands in for the deployment's user database: the test
// scripts WHICH principal each session activates as. The Role configuration
// maps that principal to a Role, and the Method's RolePermissions decide Call.
// ===========================================================================
namespace
{

/// Approves the anonymous token but binds the session to a scripted UserName principal, so that two
/// sessions against the same endpoint carry two different `UserIdentity` values. The kind is UserName
/// because the Role's identity rule is a UserName rule, and such a rule matches UserName identities only
/// (Part 18 section 4.4.4 Table 10; security review SVC-1).
class ScriptedPrincipalAuthenticator final : public ua::server::UserAuthenticator
{
public:
  explicit ScriptedPrincipalAuthenticator(std::shared_ptr<std::atomic<bool>> issuePrivileged)
    : mIssuePrivileged(std::move(issuePrivileged))
  {}

  void authenticate_async(
    ua::server::AuthnRequest /*req*/, ua::server::AuthnComplete completion) noexcept override
  {
    ua::server::UserIdentity identity;
    identity.kind = ua::server::UserTokenKind::UserName;
    if (mIssuePrivileged->load())
    {
      identity.userId = "privileged-user";
    }
    else
    {
      identity.userId = "restricted-user";
    }
    identity.displayName = identity.userId;
    completion(ua::server::make_authn_success(std::move(identity)));
  }

private:
  std::shared_ptr<std::atomic<bool>> mIssuePrivileged;
};

const NodeId privilegedCallerRoleId{1, uint32_t{9901}};
constexpr uint8_t privilegedCallerRoleBit{9};

}  // namespace

class ComplianceMethodPerUserAuthz : public ComplianceSecured
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.authenticator = std::make_shared<ScriptedPrincipalAuthenticator>(mIssuePrivileged);
    // Both principals are UserName identities, which an Anonymous rule does not match (Part 18 section
    // 4.4.4), so the Anonymous Role - which the fixture namespace's default grants access to the owning
    // Object - is also granted to authenticated users. Only the Method's own permissions then differ
    // between the two principals, which is this fixture's subject.
    auto roles =
      RoleConfiguration::from_well_known_grants({{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous},
        {WellKnownRole::Anonymous, IdentityCriteriaType::AuthenticatedUser}});
    RoleConfiguration::RoleDefinition privilegedCaller;
    privilegedCaller.roleId = privilegedCallerRoleId;
    privilegedCaller.roleBit = privilegedCallerRoleBit;
    IdentityMappingRuleType privilegedUser;
    privilegedUser.criteria_type() = IdentityCriteriaType::UserName;
    privilegedUser.criteria() = "privileged-user";
    privilegedCaller.identities.push_back(std::move(privilegedUser));
    ASSERT_TRUE(roles->add_role(std::move(privilegedCaller)));
    components.roleConfiguration = std::move(roles);
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    auto addressSpace = mServer->address_space();
    mMethodNamespace = default_ns::Namespace::create("urn:test:method:peruser", mServerThreadPool.executor());
    mMethodNamespaceIndex = addressSpace.add_namespace_sync(mMethodNamespace);

    // The Method created below carries its own node-level permissions - that is this fixture's subject -
    // but the Object owning it declares none, and a Call is authorized against both. With no namespace
    // default the Object is refused and even the PERMITTED arm returns BadUserAccessDenied. Node-level
    // permissions win over the default, so granting it leaves the subject intact.
    grant_fixture_namespace_permissions(addressSpace);

    mObjectId = NodeId{mMethodNamespaceIndex, uint32_t{9000}};
    auto objNode = addressSpace.create_node_sync(mObjectId, NodeClass::Object);
    auto obj = objNode.as<ObjectAccessor>();
    ASSERT_TRUE(obj.has_value());
    obj->set_browse_name(QualifiedName{mMethodNamespaceIndex, "PerUserTestObject"});
    obj->set_display_name(LocalizedText{"", "PerUserTestObject"});

    mMethodId = NodeId{mMethodNamespaceIndex, uint32_t{9001}};
    auto methodNode = addressSpace.create_node_sync(mMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    ASSERT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{mMethodNamespaceIndex, "PerUserTestMethod"});
    method->set_display_name(LocalizedText{"", "PerUserTestMethod"});
    method->set_executable(true);
    RolePermissionType anonymousPermissions;
    anonymousPermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymousPermissions.permissions() =
      PermissionType{{PermissionType::Bit::Browse, PermissionType::Bit::Read}};
    RolePermissionType privilegedPermissions;
    privilegedPermissions.role_id() = privilegedCallerRoleId;
    privilegedPermissions.permissions() =
      PermissionType{{PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::Call}};
    method->set_role_permissions(
      std::vector<RolePermissionType>{anonymousPermissions, privilegedPermissions});
    objNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMethodId);
    {
      auto* callSource = mMethodNamespace->find_node<Node>(mMethodId)->method_call_source();
      ASSERT_NE(callSource, nullptr);
      auto ran = mMethodRan;
      callSource->set_call_handler(
        [ran](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            cb)
        {
          ran->store(true);
          CallMethodResult r;
          cb(CallResult{std::move(r)});
        });
    }

    // Session one: the principal WITHOUT the Call permission.
    mIssuePrivileged->store(false);
    {
      CoreClient::OpenChannelConfig cfg;
      cfg.endpointUrl = mEndpointUrl;
      cfg.securityMode = MessageSecurityMode::None;
      cfg.securityPolicyId = SecurityPolicyId::None;
      mRestrictedChannel.emplace(mClient->core().open_channel_sync(std::move(cfg)));
      mRestrictedSession.emplace(mRestrictedChannel->create_session_sync({.sessionName = "RestrictedUser"}));
      mRestrictedSession->activate_sync();
    }

    // Session two: the principal WITH it. Same endpoint, same channel security, same Method.
    mIssuePrivileged->store(true);
    {
      CoreClient::OpenChannelConfig cfg;
      cfg.endpointUrl = mEndpointUrl;
      cfg.securityMode = MessageSecurityMode::None;
      cfg.securityPolicyId = SecurityPolicyId::None;
      mPrivilegedChannel.emplace(mClient->core().open_channel_sync(std::move(cfg)));
      mPrivilegedSession.emplace(mPrivilegedChannel->create_session_sync({.sessionName = "PrivilegedUser"}));
      mPrivilegedSession->activate_sync();
    }
  }

  void TearDown() override
  {
    if (mPrivilegedSession)
      (void)mPrivilegedSession->try_close_sync();
    if (mPrivilegedChannel)
      (void)mPrivilegedChannel->try_close_sync();
    if (mRestrictedSession)
      (void)mRestrictedSession->try_close_sync();
    if (mRestrictedChannel)
      (void)mRestrictedChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  std::shared_ptr<std::atomic<bool>> mIssuePrivileged{std::make_shared<std::atomic<bool>>(false)};
  std::shared_ptr<std::atomic<bool>> mMethodRan{std::make_shared<std::atomic<bool>>(false)};
  std::shared_ptr<default_ns::Namespace> mMethodNamespace;
  uint16_t mMethodNamespaceIndex{0};
  NodeId mObjectId;
  NodeId mMethodId;
  std::optional<SecureChannel> mRestrictedChannel;
  std::optional<Session> mRestrictedSession;
  std::optional<SecureChannel> mPrivilegedChannel;
  std::optional<Session> mPrivilegedSession;
};

// Part 4 section 5.11.2.4 - Bad_UserAccessDenied is the per-operation code for "access denied for the current
// user", and SVR-METH-CALL-046 makes it a per-user verdict, distinct from the user-independent
// Executable gate. Two failures are plausible and both are covered here: an implementation that never
// consults Namespace policy runs the Method for a user with no permission, and one that fails the whole
// Call service (or refuses everyone) makes the code useless as a per-user signal. The permitted leg is
// what turns the refusal from "Call is broken" into "Call is gated on the principal".
// @verifies AC-SVR-METH-CALL-046-BAD-USERACCESSDENIED
TEST_F(ComplianceMethodPerUserAuthz, METH_CALL_046_CallRefusedForUnprivilegedUserAndPermittedForPrivileged)
{
  ASSERT_FALSE(mMethodRan->load()) << "precondition: the probe body has not run yet";

  // The user WITHOUT permission.
  {
    auto result = mRestrictedSession->methods().try_call_sync(call_method(mObjectId, mMethodId));
    ASSERT_THAT(result, Good()) << "the Call service itself shall succeed; the denial is per-operation";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadUserAccessDenied))
      << "a user without the Call permission shall receive Bad_UserAccessDenied for that operation";
    EXPECT_FALSE(mMethodRan->load())
      << "the Method body shall not run for a user denied permission to Call it";
  }

  // The same Method, same endpoint, same channel security - only the principal differs.
  {
    auto result = mPrivilegedSession->methods().try_call_sync(call_method(mObjectId, mMethodId));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], Good())
      << "a user holding the Call permission shall be allowed to invoke the Method";
    EXPECT_TRUE(mMethodRan->load()) << "the permitted Call shall actually dispatch the Method body";
  }
}

// ===========================================================================
// Fixture: ComplianceMethodSecurityMode - secured server, a Method whose
// AccessRestrictions demand encryption, with both a Sign-only and a
// SignAndEncrypt session open against it.
// ===========================================================================
class ComplianceMethodSecurityMode : public ComplianceSecured
{
protected:
  void SetUp() override
  {
    ComplianceSecured::SetUp();

    auto addressSpace = mServer->address_space();
    mMethodNamespace =
      default_ns::Namespace::create("urn:test:method:securitymode", mServerThreadPool.executor());
    mMethodNamespaceIndex = addressSpace.add_namespace_sync(mMethodNamespace);

    // The Method created below carries its own node-level permissions - that is this fixture's subject -
    // but the Object owning it declares none, and a Call is authorized against both. With no namespace
    // default the Object is refused and even the PERMITTED arm returns BadUserAccessDenied. Node-level
    // permissions win over the default, so granting it leaves the subject intact.
    grant_fixture_namespace_permissions(addressSpace);

    mObjectId = NodeId{mMethodNamespaceIndex, uint32_t{8000}};
    auto objNode = addressSpace.create_node_sync(mObjectId, NodeClass::Object);
    auto obj = objNode.as<ObjectAccessor>();
    ASSERT_TRUE(obj.has_value());
    obj->set_browse_name(QualifiedName{mMethodNamespaceIndex, "SecurityModeTestObject"});
    obj->set_display_name(LocalizedText{"", "SecurityModeTestObject"});

    // Two Methods on the same Object differing ONLY in AccessRestrictions. Each body records that it
    // ran, so "the Method did not run" is an observation and not an assumption.
    const auto createProbeMethod = [&](uint32_t identifier,
                                     std::string browseName,
                                     bool encryptionRequired,
                                     std::shared_ptr<std::atomic<bool>>
                                       ran)
    {
      const NodeId methodId{mMethodNamespaceIndex, identifier};
      auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
      auto method = methodNode.as<MethodAccessor>();
      EXPECT_TRUE(method.has_value());
      method->set_browse_name(QualifiedName{mMethodNamespaceIndex, browseName});
      method->set_display_name(LocalizedText{"", browseName});
      method->set_executable(true);
      if (encryptionRequired)
      {
        methodNode.set_access_restrictions(
          AccessRestrictionType{AccessRestrictionType::Bit::EncryptionRequired});
      }
      objNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

      auto* callSource = mMethodNamespace->find_node<Node>(methodId)->method_call_source();
      EXPECT_NE(callSource, nullptr);
      callSource->set_call_handler(
        [ran](const CallMethodRequest&,
          std::shared_ptr<const MethodCallContext> /*context*/,
          std::function<void(CallResult)>
            cb)
        {
          ran->store(true);
          CallMethodResult r;
          cb(CallResult{std::move(r)});
        });
      return methodId;
    };

    mEncryptionRequiredMethodId =
      createProbeMethod(uint32_t{8001}, "EncryptionRequiredProbeMethod", true, mEncryptionRequiredRan);
    mUnrestrictedMethodId =
      createProbeMethod(uint32_t{8002}, "UnrestrictedProbeMethod", false, mUnrestrictedRan);

    // Sign-only session: signed but NOT encrypted - the stimulus the criterion names.
    {
      CoreClient::OpenChannelConfig cfg;
      cfg.endpointUrl = mEndpointUrl;
      cfg.securityMode = MessageSecurityMode::Sign;
      cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      cfg.serverCertificate = mServerCert;
      mSignChannel.emplace(mClient->core().open_channel_sync(std::move(cfg)));
      mSignSession.emplace(mSignChannel->create_session_sync({.sessionName = "MethodSignOnly"}));
      mSignSession->activate_sync();
    }

    // SignAndEncrypt session: the mode the Method's AccessRestrictions actually demand.
    {
      CoreClient::OpenChannelConfig cfg;
      cfg.endpointUrl = mEndpointUrl;
      cfg.securityMode = MessageSecurityMode::SignAndEncrypt;
      cfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
      cfg.serverCertificate = mServerCert;
      mEncryptChannel.emplace(mClient->core().open_channel_sync(std::move(cfg)));
      mEncryptSession.emplace(mEncryptChannel->create_session_sync({.sessionName = "MethodSignAndEncrypt"}));
      mEncryptSession->activate_sync();
    }
  }

  void TearDown() override
  {
    if (mEncryptSession)
      (void)mEncryptSession->try_close_sync();
    if (mEncryptChannel)
      (void)mEncryptChannel->try_close_sync();
    if (mSignSession)
      (void)mSignSession->try_close_sync();
    if (mSignChannel)
      (void)mSignChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  std::shared_ptr<std::atomic<bool>> mEncryptionRequiredRan{std::make_shared<std::atomic<bool>>(false)};
  std::shared_ptr<std::atomic<bool>> mUnrestrictedRan{std::make_shared<std::atomic<bool>>(false)};
  std::shared_ptr<default_ns::Namespace> mMethodNamespace;
  uint16_t mMethodNamespaceIndex{0};
  NodeId mObjectId;
  NodeId mEncryptionRequiredMethodId;
  NodeId mUnrestrictedMethodId;
  std::optional<SecureChannel> mSignChannel;
  std::optional<Session> mSignSession;
  std::optional<SecureChannel> mEncryptChannel;
  std::optional<Session> mEncryptSession;
};

// Part 4 section 5.11.2.4 - Bad_SecurityModeInsufficient when "the security mode of the channel is
// insufficient" for the Method. Sign-only is the interesting case, not None: a channel that is
// authenticated and integrity-protected looks secure, so an implementation that treats
// EncryptionRequired as "any security will do" - or that only screens the None endpoint - invokes the
// Method with its arguments and results travelling in clear text. The two controls fix the meaning of
// the refusal: the Sign session can call an unrestricted Method, and the restricted Method is callable
// once the channel is encrypted.
// @verifies AC-SVR-METH-CALL-047-BAD-SECURITYMODEINSUFFICIENT
TEST_F(ComplianceMethodSecurityMode, METH_CALL_047_EncryptionRequiringMethodIsRefusedOnSignOnlyChannel)
{
  // Control: the Sign-only session is a working Call surface.
  {
    auto result = mSignSession->methods().try_call_sync(call_method(mObjectId, mUnrestrictedMethodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: a Method with no AccessRestrictions is callable "
                                              "over a Sign-only channel";
    ASSERT_TRUE(mUnrestrictedRan->load()) << "control: the probe body records its own invocation";
  }

  // Obligation: the same session, a Method whose AccessRestrictions demand encryption.
  {
    auto result = mSignSession->methods().try_call_sync(call_method(mObjectId, mEncryptionRequiredMethodId));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadSecurityModeInsufficient))
      << "a Method requiring encryption shall be refused with Bad_SecurityModeInsufficient on a "
         "Sign-only channel";
    EXPECT_FALSE(mEncryptionRequiredRan->load())
      << "the Method body shall not run when the channel security mode is insufficient";
  }

  // Control: the same Method over SignAndEncrypt succeeds, so the refusal above is about the channel's
  // security mode and not about the Method being uncallable.
  {
    auto result =
      mEncryptSession->methods().try_call_sync(call_method(mObjectId, mEncryptionRequiredMethodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], Good())
      << "control: the encryption-requiring Method is callable over a SignAndEncrypt channel";
    EXPECT_TRUE(mEncryptionRequiredRan->load()) << "control: the permitted Call dispatches the Method body";
  }
}

// ===========================================================================
// Obligation tests: response framing and objectId screening
// ===========================================================================

// Part 4 section 5.11.2.2 - "The list shall be empty if the statusCode Severity is Bad." SVR-METH-CALL-021
// puts the stripping on the response framer, "regardless of what the Method returned", so the Method's own
// declared OutputArguments are exactly the case that catches a framer which reshapes the list instead of
// emptying it: an implementation that pads or truncates outputArguments to the declared arity hands the
// Client two default-constructed Variants beside a Bad code, and one that simply forwards the handler's
// CallMethodResult hands it the half-computed real values. The Good leg first proves those declared
// outputs do reach the Client, so the emptiness on the Bad leg is caused by the severity and not by the
// outputs never having travelled. (This SDK adopts the handler's result whole - D-CALL-RESPONSE-FRAMER-
// DOES-NOT-STRIP - so this is expected to be red until the stripping lands.)
// @verifies AC-SVR-METH-CALL-021-BAD-MEANS-NO-OUTPUTS
TEST_F(ComplianceWithNodes, METH_CALL_021_DeclaredOutputsDroppedWhenTheMethodFailsWithBadStatus)
{
  auto addressSpace = mServer.server().address_space();

  auto ran = std::make_shared<std::atomic<bool>>(false);
  auto shouldFail = std::make_shared<std::atomic<bool>>(false);

  // A Method that DECLARES two Int32 outputs in the model, so the server sees an output shape of its own
  // to be tempted by, and whose body always computes both before deciding its status.
  const NodeId methodId{mTestNamespaceIndex, uint32_t{3700}};
  auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "TwoDeclaredOutputsMethod"});
  method->set_display_name(LocalizedText{"", "TwoDeclaredOutputsMethod"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

  const NodeId outputArgumentsId{mTestNamespaceIndex, uint32_t{3701}};
  auto outputNode = addressSpace.create_node_sync(outputArgumentsId, NodeClass::Variable);
  auto outputVariable = outputNode.as<VariableAccessor>();
  ASSERT_TRUE(outputVariable.has_value());
  outputVariable->set_browse_name(QualifiedName{0, "OutputArguments"});
  outputVariable->set_display_name(LocalizedText{"", "OutputArguments"});
  outputVariable->set_data_type(NodeId{DataTypeId::Argument});
  outputVariable->set_value_rank(ValueRank{1});
  {
    Array<RefStructure<Structure>> arguments;
    for (std::string_view name : {"FirstOut", "SecondOut"})
    {
      auto argument = std::make_unique<Argument>();
      argument->name() = String{name};
      argument->data_type() = NodeId{DataTypeId::Int32};
      argument->value_rank() = -1;
      arguments.push_back(RefStructure<Structure>{std::move(argument)});
    }
    outputVariable->write_value_sync(DataValue{Variant{std::move(arguments)}});
  }
  methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, outputArgumentsId);

  {
    auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [ran, shouldFail](const CallMethodRequest&,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        ran->store(true);
        CallMethodResult r;
        // Both outputs are computed EVERY time; only the verdict differs.
        r.output_arguments().resize(2);
        r.output_arguments()[0] = Variant{int32_t{111}};
        r.output_arguments()[1] = Variant{int32_t{222}};
        if (shouldFail->load())
          r.status_code() = Status::BadOutOfRange;
        cb(CallResult{std::move(r)});
      });
  }

  // Control: with a Good verdict the two declared outputs reach the Client intact.
  {
    auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, methodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: the Method succeeds when its body says so";
    ASSERT_TRUE(ran->load()) << "control: the probe body records its own invocation";
    ASSERT_EQ(resp.results()[0].output_arguments().size(), 2u)
      << "control: a Good result carries the outputArguments the Method computed";
    EXPECT_EQ(resp.results()[0].output_arguments()[0].as<int32_t>(), 111);
    EXPECT_EQ(resp.results()[0].output_arguments()[1].as<int32_t>(), 222);
  }

  ran->store(false);
  shouldFail->store(true);

  // Obligation: the same Method, the same two computed outputs, a Bad verdict.
  {
    auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, methodId));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    // The body having run is what makes the emptiness below an observation of the framer: the outputs
    // really were populated, so an empty list can only mean they were stripped.
    ASSERT_TRUE(ran->load()) << "the Method body must have run and populated its outputs";
    ASSERT_THAT(resp.results()[0], HasStatus(Status::BadOutOfRange))
      << "the handler's Bad status must reach the Client as that operation's result";
    EXPECT_TRUE(resp.results()[0].output_arguments().empty())
      << "outputArguments shall be empty when the statusCode Severity is Bad - neither the Method's "
         "partial values nor a list padded to the declared OutputArguments arity";
  }
}

// Part 4 section 5.11.2.4 - Bad_NodeIdInvalid is the answer to an `objectId` that is syntactically malformed,
// against Bad_NodeIdUnknown for one that is well formed and names nothing. OPC 10000-6 section 5.2.2.9
// defines a null identifier for each of the four identifier types, and the Guid and Opaque encodings are the
// ones a null check written as a numeric-zero (or empty-string) comparison silently misses, even though they
// are the same malformed objectId on the wire. The second conjunct is the one with teeth: an implementation
// that screens the objectId only for the response code, after resolving methodId and dispatching, reports
// Bad_NodeIdInvalid with the Method's side effects already committed. (This SDK performs no null-objectId
// check on the Call path - D-CALL-DOES-NOT-MAP-A-NULL - so this is expected to be red until it does.)
// @relation(AC-SVR-METH-CALL-040-BAD-NODEIDINVALID, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_040_MalformedObjectIdIsBadNodeIdInvalidAndTheMethodDoesNotRun)
{
  auto addressSpace = mServer.server().address_space();

  auto ran = std::make_shared<std::atomic<bool>>(false);

  const NodeId probeMethodId{mTestNamespaceIndex, uint32_t{3710}};
  auto methodNode = addressSpace.create_node_sync(probeMethodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "MalformedObjectIdProbeMethod"});
  method->set_display_name(LocalizedText{"", "MalformedObjectIdProbeMethod"});
  method->set_executable(true);
  addressSpace.find_node_sync(mTestFolderId)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, probeMethodId);
  {
    auto* callSource = mTestNamespace->find_node<Node>(probeMethodId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [ran](const CallMethodRequest&,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        ran->store(true);
        CallMethodResult r;
        cb(CallResult{std::move(r)});
      });
  }

  // Control: with its owning Object the probe dispatches, so "did not run" below is an observation of the
  // body and not of a handler that was never reachable.
  {
    auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, probeMethodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: the probe Method is callable on its own Object";
    ASSERT_TRUE(ran->load()) << "control: the probe body records its own invocation";
  }

  const auto expectRefusedWithoutRunning = [this, &probeMethodId, &ran](
                                             const NodeId& malformedObjectId, const char* what)
  {
    ASSERT_TRUE(malformedObjectId.is_null())
      << what << " - the encoding must itself be a null (malformed) NodeId";
    ran->store(false);

    auto result = mSession->methods().try_call_sync(call_method(malformedObjectId, probeMethodId));
    ASSERT_THAT(result, Good()) << what << " - the Call service itself shall succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadNodeIdInvalid))
      << what << " - a syntactically invalid objectId shall be Bad_NodeIdInvalid, not Bad_NodeIdUnknown";
    EXPECT_FALSE(ran->load()) << what << " - the Method shall not run for a malformed objectId";
  };

  expectRefusedWithoutRunning(NodeId{uint16_t{0}, Guid{}}, "the null Guid encoding as objectId");
  expectRefusedWithoutRunning(NodeId{uint16_t{0}, ByteString{}}, "the null Opaque encoding as objectId");
}

// Part 4 section 5.11.1 - "A Method shall be a component of an Object." Call takes an (objectId, methodId)
// pair, so a Method that no Object or ObjectType sources a HasComponent to is browsable and callable-looking
// but unreachable by any conforming Client. Two model-construction mistakes produce exactly that and both are
// checked here: hanging a Method off a folder with Organizes (hierarchical, so it browses like a child,
// but it is not a component), and sourcing the HasComponent from a Variable or another Method rather than
// from an Object or an ObjectType. The walk is bounded because a non-conforming model may contain a loop
// and a harness that hangs reports nothing; it is a SAMPLE of the model and the name says so.
// @verifies AC-SVR-METH-GEN-001-METHOD-HAS-PARENT
TEST_F(ComplianceWithNodes, METH_GEN_001_EverySampledMethodIsAComponentOfAnObjectOrObjectType)
{
  struct Edge
  {
    NodeId source;
    NodeId referenceType;
    NodeId target;
    NodeClass targetClass;
  };

  // Bounded so a cyclic model cannot hang the run, and small enough that the walk stays well inside the
  // per-Session request allowance D-SERVER-SEQUENTIAL-REQUESTS-TOO-BUSY describes.
  constexpr std::size_t nodeBudget = 80;

  std::vector<Edge> edges;
  std::vector<std::string> browseFailures;
  std::map<std::string, NodeClass> nodeClasses;

  const NodeId rootId{ObjectId::RootFolder};
  nodeClasses[ua::to_string(rootId)] = NodeClass::Object;

  {
    std::deque<NodeId> queue{rootId};
    std::set<std::string> visited{ua::to_string(rootId)};
    while (!queue.empty() && visited.size() < nodeBudget)
    {
      const auto current = queue.front();
      queue.pop_front();

      BrowseDescription desc;
      desc.node_id() = current;
      desc.browse_direction() = BrowseDirection::Forward;
      desc.reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
      desc.include_subtypes() = true;
      desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);

      BrowseRequest req;
      req.nodes_to_browse().push_back(std::move(desc));
      auto result = mSession->view().try_browse_sync(std::move(req));
      if (result.is_bad())
      {
        browseFailures.push_back(
          ua::to_string(current) + " -> status " + std::to_string(result.status_code().as_uint32()));
        continue;
      }
      if (result.value().results().empty())
        continue;

      for (const auto& ref : result.value().results()[0].references())
      {
        if (!ref.is_forward())
          continue;
        Edge edge;
        edge.source = current;
        edge.referenceType = ref.reference_type_id();
        edge.target = ref.node_id().node_id();
        edge.targetClass = ref.node_class();
        nodeClasses[ua::to_string(edge.target)] = edge.targetClass;
        edges.push_back(edge);
        if (visited.insert(ua::to_string(edge.target)).second)
          queue.push_back(edge.target);
      }
    }
  }

  // A truncated walk makes every assertion below weaker than it reads, so it fails rather than passes.
  ASSERT_TRUE(browseFailures.empty()) << "the walk could not complete: " << browseFailures.size()
                                      << " Browse(s) failed, first: " << browseFailures.front();
  ASSERT_FALSE(edges.empty()) << "the walk reached no references at all";

  // "HasComponent (or subtype thereof)" is the reference the obligation names, so the subtypes are read
  // from the server's own ReferenceType hierarchy rather than assumed to be just HasComponent.
  std::set<std::string> componentReferenceTypes{ua::to_string(NodeId{ReferenceTypeId::HasComponent})};
  {
    std::deque<NodeId> queue{NodeId{ReferenceTypeId::HasComponent}};
    while (!queue.empty())
    {
      const auto current = queue.front();
      queue.pop_front();

      BrowseDescription desc;
      desc.node_id() = current;
      desc.browse_direction() = BrowseDirection::Forward;
      desc.reference_type_id() = NodeId{ReferenceTypeId::HasSubtype};
      desc.include_subtypes() = true;
      desc.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);

      BrowseRequest req;
      req.nodes_to_browse().push_back(std::move(desc));
      auto result = mSession->view().try_browse_sync(std::move(req));
      ASSERT_THAT(result, Good()) << "browsing the HasComponent subtype closure";
      if (result.value().results().empty())
        continue;
      for (const auto& ref : result.value().results()[0].references())
      {
        if (!ref.is_forward())
          continue;
        const auto subtype = ref.node_id().node_id();
        if (componentReferenceTypes.insert(ua::to_string(subtype)).second)
          queue.push_back(subtype);
      }
    }
  }

  std::vector<NodeId> methods;
  {
    std::set<std::string> seen;
    for (const auto& edge : edges)
    {
      if (edge.targetClass == NodeClass::Method && seen.insert(ua::to_string(edge.target)).second)
        methods.push_back(edge.target);
    }
  }
  ASSERT_FALSE(methods.empty()) << "the sample reached no Method at all, so the invariant below would "
                                   "hold vacuously";
  // The sample must include Methods this fixture built, not only whatever NS0 happened to be reached
  // first; otherwise the walk could shrink to nothing and still read green.
  {
    bool sawTestMethod = false;
    for (const auto& methodId : methods)
      sawTestMethod = sawTestMethod || (methodId == mTestMethodId);
    ASSERT_TRUE(sawTestMethod) << "the sample must reach TestMethod, or it is too small to mean anything";
  }

  std::string orphans;
  std::size_t orphanCount = 0;
  for (const auto& methodId : methods)
  {
    bool component = false;
    for (const auto& edge : edges)
    {
      if (!(edge.target == methodId))
        continue;
      if (componentReferenceTypes.count(ua::to_string(edge.referenceType)) == 0)
        continue;
      const auto sourceClass = nodeClasses.find(ua::to_string(edge.source));
      if (sourceClass == nodeClasses.end())
        continue;
      if (sourceClass->second == NodeClass::Object || sourceClass->second == NodeClass::ObjectType)
      {
        component = true;
        break;
      }
    }
    if (!component)
    {
      ++orphanCount;
      orphans += " " + ua::to_string(methodId);
    }
  }

  EXPECT_EQ(orphanCount, 0u) << "every Method shall be the target of a HasComponent (or subtype) sourced "
                                "from an Object or an ObjectType; these were not:"
                             << orphans;
}

// Part 4 section 5.11.2.2 - "The list shall be empty if the statusCode Severity is Bad." The obligation is
// keyed on the SEVERITY, so it holds for every Bad code a Method can return and not only for the one an
// implementation happened to be written against. A framer that empties the list behind a comparison with a
// particular code, or that only reshapes the results the server itself synthesises while trusting a handler
// that reports a code of its own, satisfies a single-code test and still hands the Client half-computed
// values for every other failure. The Good leg proves the two computed outputs really do travel to the
// Client, so an empty list on the Bad legs can only be the stripping and not a Method whose outputs never
// left the server.
// @relation(AC-SVR-METH-CALL-021-BAD-MEANS-NO-OUTPUTS, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_021_EveryBadSeverityCodeYieldsEmptyOutputArguments)
{
  auto addressSpace = mServer.server().address_space();
  auto folderNode = addressSpace.find_node_sync(mTestFolderId);

  // Every probe computes the SAME two outputs and differs only in the verdict it reports, so the verdict is
  // the only variable across the legs below.
  const auto createProbeMethod =
    [&](uint32_t identifier, std::string browseName, Status verdict, std::shared_ptr<std::atomic<bool>> ran)
  {
    const NodeId methodId{mTestNamespaceIndex, identifier};
    auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    EXPECT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{mTestNamespaceIndex, browseName});
    method->set_display_name(LocalizedText{"", browseName});
    method->set_executable(true);
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

    auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
    EXPECT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [ran, verdict](const CallMethodRequest&,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        ran->store(true);
        CallMethodResult r;
        r.output_arguments().resize(2);
        r.output_arguments()[0] = Variant{int32_t{101}};
        r.output_arguments()[1] = Variant{int32_t{202}};
        r.status_code() = verdict;
        cb(CallResult{std::move(r)});
      });
    return methodId;
  };

  // Control: the identically shaped probe that succeeds. Its outputs reach the Client, so the emptiness
  // asserted below is caused by the severity and not by outputs that never travelled.
  {
    auto ran = std::make_shared<std::atomic<bool>>(false);
    const NodeId goodMethodId =
      createProbeMethod(uint32_t{3800}, "SucceedsWithTwoOutputsMethod", Status::Good, ran);
    auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, goodMethodId));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: the probe succeeds when its body says so";
    ASSERT_TRUE(ran->load()) << "control: the probe body records its own invocation";
    ASSERT_EQ(resp.results()[0].output_arguments().size(), 2u)
      << "control: a Good result carries the outputArguments the Method computed";
    EXPECT_EQ(resp.results()[0].output_arguments()[0].as<int32_t>(), 101);
    EXPECT_EQ(resp.results()[0].output_arguments()[1].as<int32_t>(), 202);
  }

  struct BadVerdict
  {
    Status code;
    uint32_t identifier;
    const char* browseName;
    const char* what;
  };

  const std::vector<BadVerdict> badVerdicts{
    {Status::BadInternalError, uint32_t{3801}, "FailsInternalErrorMethod", "Bad_InternalError"},
    {Status::BadOutOfRange, uint32_t{3802}, "FailsOutOfRangeMethod", "Bad_OutOfRange"},
    {Status::BadInvalidState, uint32_t{3803}, "FailsInvalidStateMethod", "Bad_InvalidState"},
    {Status::BadNotSupported, uint32_t{3804}, "FailsNotSupportedMethod", "Bad_NotSupported"},
    {Status::BadResourceUnavailable,
      uint32_t{3805},
      "FailsResourceUnavailableMethod",
      "Bad_ResourceUnavailable"}};
  ASSERT_FALSE(badVerdicts.empty()) << "the table of Bad verdicts must not be empty";

  for (const auto& verdict : badVerdicts)
  {
    auto ran = std::make_shared<std::atomic<bool>>(false);
    const NodeId methodId = createProbeMethod(verdict.identifier, verdict.browseName, verdict.code, ran);

    auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, methodId));
    ASSERT_THAT(result, Good()) << verdict.what << " - the Call service itself shall succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    // The body having run is what makes the emptiness an observation of the framer: the outputs really
    // were populated, so an empty list can only mean they were stripped.
    ASSERT_TRUE(ran->load()) << verdict.what << " - the Method body must have run and populated its outputs";
    ASSERT_TRUE(resp.results()[0].status_code().is_bad())
      << verdict.what << " - the Method's Bad verdict must reach the Client as that operation's severity";
    EXPECT_TRUE(resp.results()[0].output_arguments().empty())
      << verdict.what
      << " - outputArguments shall be empty whenever the statusCode Severity is Bad, whichever Bad code "
         "the Method returned";
  }
}

// Part 4 section 5.11.2.2 (Table 65, inputArguments): "Fewer arguments than the total number of input
// arguments defined may be passed by the Client when optional input arguments are defined. A Method may
// define input arguments as optional by including HasOptionalInputArgumentDescription references to argument
// metadata." Part 3 section 5.7.3 fixes the shape used here - the reference targets a Variable whose
// BrowseName is the Argument's name, and "optional input arguments shall always follow any non-optional input
// arguments" - and section 5.11.2.4 keys Bad_ArgumentsMissing on the NON-OPTIONAL inputs alone. Both halves
// are asserted because either one alone is satisfiable by a wrong implementation: a server that counts
// declared arguments and ignores the metadata refuses a legal short call, and a server that simply accepts
// any short list has turned every argument into an optional one. The metadata Variable may supply a default
// for the omitted argument (Part 3 Figure 16), so the count the body observes is logged rather than asserted.
// @relation(AC-SVR-METH-CALL-014-OPTIONAL-ARGUMENTS-OMITTED, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_014_TrailingOptionalInputArgumentMayBeOmitted)
{
  auto addressSpace = mServer.server().address_space();
  auto folderNode = addressSpace.find_node_sync(mTestFolderId);

  auto ran = std::make_shared<std::atomic<bool>>(false);
  auto seenArgumentCount = std::make_shared<std::atomic<size_t>>(0);

  const NodeId methodId{mTestNamespaceIndex, uint32_t{3900}};
  auto methodNode = addressSpace.create_node_sync(methodId, NodeClass::Method);
  auto method = methodNode.as<MethodAccessor>();
  ASSERT_TRUE(method.has_value());
  method->set_browse_name(QualifiedName{mTestNamespaceIndex, "OptionalTailMethod"});
  method->set_display_name(LocalizedText{"", "OptionalTailMethod"});
  method->set_executable(true);
  folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, methodId);

  // Two declared inputs, the optional one LAST (Part 3 section 5.7.3: optional inputs follow the non-optional
  // ones).
  const NodeId inputArgumentsId{mTestNamespaceIndex, uint32_t{3901}};
  auto inputNode = addressSpace.create_node_sync(inputArgumentsId, NodeClass::Variable);
  auto inputVariable = inputNode.as<VariableAccessor>();
  ASSERT_TRUE(inputVariable.has_value());
  inputVariable->set_browse_name(QualifiedName{0, "InputArguments"});
  inputVariable->set_display_name(LocalizedText{"", "InputArguments"});
  inputVariable->set_data_type(NodeId{DataTypeId::Argument});
  inputVariable->set_value_rank(ValueRank{1});
  {
    Array<RefStructure<Structure>> arguments;
    for (std::string_view name : {"Required", "Optional"})
    {
      auto argument = std::make_unique<Argument>();
      argument->name() = String{name};
      argument->data_type() = NodeId{DataTypeId::Int32};
      argument->value_rank() = -1;
      arguments.push_back(RefStructure<Structure>{std::move(argument)});
    }
    inputVariable->write_value_sync(DataValue{Variant{std::move(arguments)}});
  }
  inputNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::PropertyType});
  methodNode.add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, inputArgumentsId);

  // The metadata that MAKES the trailing argument optional: a Variable whose BrowseName is that Argument's
  // name, referenced from the Method by HasOptionalInputArgumentDescription (Part 3
  // section 5.7.2/section 5.7.3 - same DataType as the Argument it describes).
  const NodeId optionalDescriptionId{mTestNamespaceIndex, uint32_t{3902}};
  auto descriptionNode = addressSpace.create_node_sync(optionalDescriptionId, NodeClass::Variable);
  auto description = descriptionNode.as<VariableAccessor>();
  ASSERT_TRUE(description.has_value());
  description->set_browse_name(QualifiedName{mTestNamespaceIndex, "Optional"});
  description->set_display_name(LocalizedText{"", "Optional"});
  description->set_data_type(NodeId{DataTypeId::Int32});
  description->write_value_sync(DataValue{Variant{int32_t{0}}});
  descriptionNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
  methodNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasOptionalInputArgumentDescription}, optionalDescriptionId);

  {
    auto* callSource = mTestNamespace->find_node<Node>(methodId)->method_call_source();
    ASSERT_NE(callSource, nullptr);
    callSource->set_call_handler(
      [ran, seenArgumentCount](const CallMethodRequest& request,
        std::shared_ptr<const MethodCallContext> /*context*/,
        std::function<void(CallResult)>
          cb)
      {
        ran->store(true);
        seenArgumentCount->store(request.input_arguments().size());
        CallMethodResult r;
        cb(CallResult{std::move(r)});
      });
  }

  // Control: the full list dispatches, so "the call succeeded" below is an observation of this Method
  // running and not of a Method that can never be reached.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(mTestFolderId, methodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}));
    ASSERT_THAT(result, Good());
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], Good()) << "control: supplying both declared arguments is a valid call";
    ASSERT_TRUE(ran->load()) << "control: the probe body records its own invocation";
  }

  // The stimulus: only the non-optional argument is passed, the optional tail omitted.
  ran->store(false);
  seenArgumentCount->store(0);
  {
    auto result =
      mSession->methods().try_call_sync(call_method(mTestFolderId, methodId, {Variant{int32_t{1}}}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], Good())
      << "omitting a TRAILING OPTIONAL input argument is a legal call - the Method declares the argument "
         "optional through HasOptionalInputArgumentDescription, and a server that treats every declared "
         "input as required makes that metadata unusable";
    EXPECT_TRUE(ran->load()) << "the Method must actually be invoked when only the optional tail is omitted";
    // The metadata Variable may carry a default for the omitted argument, so the arity the body observes is
    // reported rather than constrained.
    GTEST_LOG_(INFO) << "input arguments delivered to the Method body for the short call: "
                     << seenArgumentCount->load();
  }

  // ...and the permission stops at the optional tail: dropping the REQUIRED argument is still refused, and
  // still without running the Method.
  ran->store(false);
  seenArgumentCount->store(0);
  {
    auto result = mSession->methods().try_call_sync(call_method(mTestFolderId, methodId, {}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    EXPECT_THAT(resp.results()[0], HasStatus(Status::BadArgumentsMissing))
      << "omitting the NON-OPTIONAL argument shall still return Bad_ArgumentsMissing - optional metadata on "
         "the tail is not permission to send a short list";
    EXPECT_FALSE(ran->load()) << "the Method shall not run when a non-optional input argument is missing";
  }
}

// Part 4 section 5.11.2.2 (Table 65, inputArgumentResults): "This list is empty unless the operation level
// result is Bad_InvalidArgument. If this list is populated, it has the same length as the inputArguments
// list." The list is POSITIONAL, so it is complete or it is nothing: a server that returns only the offending
// arguments puts every diagnosis against the wrong parameter, and one that always sizes it to the arity (a
// vector of Goods beside a Bad_ArgumentsMissing, or beside a successful call) tells a client to look for an
// argument fault that does not exist. The Bad_InvalidArgument leg puts the wrong-typed value SECOND so that a
// truncated or re-ordered list is distinguishable from a correct one, and the remaining legs are the codes
// the SERVER itself decides, so none of them is an assertion about a handler's own result.
// @relation(AC-SVR-METH-CALL-022-INPUTARGUMENTRESULTS-SHAPE, scope=function)
TEST_F(ComplianceWithNodes, METH_CALL_022_InputArgumentResultsAreCompleteOnInvalidArgumentAndEmptyOtherwise)
{
  // Leg 1 - Bad_InvalidArgument: one entry per SUPPLIED input argument, in order.
  {
    auto result = mSession->methods().try_call_sync(
      call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{String{"not an int"}}}));
    ASSERT_THAT(result, Good()) << "Service-level should succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], HasStatus(Status::BadInvalidArgument))
      << "a wrong-typed input argument is reported at the operation level as Bad_InvalidArgument";
    ASSERT_EQ(resp.results()[0].input_argument_results().size(), 2u)
      << "inputArgumentResults is positional: when populated it has the same length as inputArguments, so a "
         "list holding only the offending argument diagnoses the wrong parameter";
    EXPECT_TRUE(resp.results()[0].input_argument_results()[0].is_good())
      << "the FIRST argument was well-typed, so its entry must be Good - an entry per argument, in order";
    EXPECT_THAT(resp.results()[0].input_argument_results()[1], HasStatus(Status::BadTypeMismatch))
      << "the SECOND argument is the wrong type, so the fault must be recorded at index 1";
  }

  // Every other outcome the server decides for itself: two argument-count refusals, an Executable refusal
  // and a successful call. None of them is Bad_InvalidArgument, so none of them may carry the list.
  size_t legsRun = 0;
  const auto expectNoInputArgumentResults = [&](const char* what, ua::CallRequest request, Status expected)
  {
    auto result = mSession->methods().try_call_sync(std::move(request));
    ASSERT_THAT(result, Good()) << what << " - the Call service itself shall succeed";
    auto resp = std::move(result).value();
    ASSERT_EQ(resp.results().size(), 1u);
    ASSERT_THAT(resp.results()[0], HasStatus(expected))
      << what
      << " - the leg must produce the operation-level result it was built for, or it says nothing "
         "about inputArgumentResults";
    EXPECT_EQ(resp.results()[0].input_argument_results().size(), 0u)
      << what
      << " - inputArgumentResults shall be empty unless the operation level result is Bad_InvalidArgument; a "
         "populated list here sends a client hunting for an argument fault that was never diagnosed";
    ++legsRun;
  };

  expectNoInputArgumentResults("a call missing a required argument (Bad_ArgumentsMissing)",
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}}),
    Status::BadArgumentsMissing);
  expectNoInputArgumentResults("a call with an extra argument (Bad_TooManyArguments)",
    call_method(
      mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}, Variant{int32_t{3}}}),
    Status::BadTooManyArguments);
  expectNoInputArgumentResults("a call on a non-executable Method (Bad_NotExecutable)",
    call_method(mTestFolderId, mNonExecutableMethodId),
    Status::BadNotExecutable);
  expectNoInputArgumentResults("a successful call (Good)",
    call_method(mTestFolderId, mTestMethodId, {Variant{int32_t{1}}, Variant{int32_t{2}}}),
    Status::Good);

  EXPECT_EQ(legsRun, 4u) << "every non-Bad_InvalidArgument leg must have been driven to completion";
}
