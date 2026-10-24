// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for the BrowseName of a configured Role's Object under the RoleSet Object.
///
/// A Role outside namespace 0 is published under RoleSet with the BrowseName its RoleDefinition carries
/// and a DisplayName of the same text (OPC 10000-3 5.2.1, Table 7: both Mandatory). A Role without one,
/// or whose BrowseName another child of RoleSet already has (OPC 10000-18 4.2.2), is not created and is
/// logged, and its permissions still apply. AddRole records the BrowseName it builds in the definition it
/// registers, and an Object that already exists keeps its own BrowseName.

#include <gtest/gtest.h>

#include "ua_application_configuration.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_localized_text.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_message_security_mode.h"
#include "ua_method_id.h"
#include "ua_node.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_role_set_population.h"
#include "ua_server_authentication.h"
#include "ua_server_impl.h"
#include "ua_to_string.h"

#include "server_impl_test_access.h"
#include "test_utilities.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "test_components.h"

using namespace ua;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

/// Records each entry's level, message and "role_id" field; the field's view is valid only during the call.
class RoleLogSink : public LogSink
{
public:
  struct Record
  {
    LogLevel level;
    std::string message;
    std::string roleId;
  };

  void log(const LogEntry& entry) override
  {
    std::string roleId;
    for (const auto& field : entry.fields)
    {
      if (field.key == "role_id")
      {
        if (const auto* text = std::get_if<std::string_view>(&field.value))
        {
          roleId = std::string{*text};
        }
      }
    }
    const std::lock_guard lock{mMutex};
    mRecords.push_back({entry.level, entry.message, std::move(roleId)});
  }

  /// The number of Warning entries about the Role @p roleId that report it is not created under RoleSet.
  size_t not_created_warnings(const NodeId& roleId)
  {
    const std::string roleText = to_string(roleId);
    const std::lock_guard lock{mMutex};
    return static_cast<size_t>(std::count_if(mRecords.begin(),
      mRecords.end(),
      [&roleText](const Record& record)
      {
        return record.level == LogLevel::Warning && record.roleId == roleText &&
               record.message.find("is not created under RoleSet") != std::string::npos;
      }));
  }

private:
  std::mutex mMutex;
  std::vector<Record> mRecords;
};

shared_ptr<ServerImpl> create_server(boost::asio::any_io_executor executor,
  std::shared_ptr<RoleConfiguration> roleConfiguration, std::shared_ptr<RoleLogSink> sink = nullptr,
  bool roleManagement = false)
{
  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  CombinedConfig frozen;
  frozen.identity = ua::ApplicationIdentity::load_default();
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(appCfg));
  ServerConfig serverConfig;
  serverConfig.maxConnections = 100;
  serverConfig.roleManagementEnabled = roleManagement;
  frozen.server = std::move(serverConfig);
  ServerComponents components{.crypto = ua::test_helpers::test_crypto()};
  components.roleConfiguration = std::move(roleConfiguration);
  components.logSink = std::move(sink);
  components.logLevel = LogLevel::Warning;
  return ServerImpl::create(executor, std::move(frozen), std::move(components));
}

RoleConfiguration::RoleDefinition custom_role(NodeId roleId, uint8_t roleBit, QualifiedName browseName = {})
{
  RoleConfiguration::RoleDefinition definition;
  definition.roleId = std::move(roleId);
  definition.roleBit = roleBit;
  definition.browseName = std::move(browseName);
  return definition;
}

/// The targets of the RoleSet Object's forward HasComponent References.
std::vector<NodeId> role_set_children(AddressSpace& addressSpace)
{
  std::vector<NodeId> children;
  auto roleSet = addressSpace.try_find_node_sync(NodeId{ObjectId::Server_ServerCapabilities_RoleSet});
  if (!roleSet)
    return children;
  auto references = roleSet.value().try_get_references_sync();
  if (!references)
    return children;
  for (const auto& reference : references.value())
  {
    if (reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasComponent})
      children.push_back(reference.target_id().node_id());
  }
  return children;
}

bool contains(const std::vector<NodeId>& ids, const NodeId& id)
{
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}

/// The DisplayName of @p node, or a null LocalizedText when it has none.
LocalizedText display_name_of(const NodeAccessor& node)
{
  const Variant value = node.read_attribute(AttributeId::DisplayName);
  const auto* text = value.try_as<LocalizedText>();
  return text ? *text : LocalizedText{};
}

CallResult call_add_role(AddressSpace& addressSpace, std::string_view roleName, uint16_t namespaceIndex)
{
  CallMethodRequest request;
  request.object_id() = NodeId{ObjectId::Server_ServerCapabilities_RoleSet};
  request.method_id() = NodeId{MethodId::Server_ServerCapabilities_RoleSet_AddRole};
  Array<Variant> arguments;
  arguments.payload().push_back(Variant{String{roleName}});
  arguments.payload().push_back(Variant{addressSpace.namespace_array().get_namespace_uri(namespaceIndex)});
  request.input_arguments() = std::move(arguments);

  auto methodNode = addressSpace.try_find_node_sync(request.method_id());
  if (!methodNode)
    return CallResult{methodNode.status_code()};
  auto method = methodNode.value().as<MethodAccessor>();
  if (!method)
    return CallResult{StatusCode{Status::BadNodeClassInvalid}};
  auto context = std::make_shared<MethodCallContext>();
  context->channelSecurityMode = MessageSecurityMode::SignAndEncrypt;
  std::promise<CallResult> promise;
  method->call_async(
    request, context, [&promise](CallResult result) { promise.set_value(std::move(result)); });
  return promise.get_future().get();
}

}  // namespace

// A configured Role outside namespace 0 is published with the BrowseName its definition carries and a
// DisplayName of the same text with no locale. Control: the Object is a child of RoleSet, so the names are
// read from the Object start-up created.
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-03-NAMED-ROLE-PUBLISHED, scope=function)
TEST(RoleSetBrowseName, ANamedConfiguredRoleObjectHasThatBrowseNameAndDisplayName)
{
  const NodeId roleId{1, 42100u};
  auto roleConfiguration = std::make_shared<RoleConfiguration>();
  ASSERT_TRUE(roleConfiguration->add_role(custom_role(roleId, 40, QualifiedName{1, "PlantOperator"})));
  boost::asio::thread_pool pool;
  auto server = create_server(pool.get_executor(), roleConfiguration);
  ServerImplTestAccess access{*server};

  ASSERT_TRUE(contains(role_set_children(access.address_space()), roleId));
  auto role = access.address_space().try_find_node_sync(roleId);
  ASSERT_TRUE(role.is_good());
  EXPECT_EQ(role.value().get_browse_name(), (QualifiedName{1, "PlantOperator"}));
  const LocalizedText displayName = display_name_of(role.value());
  EXPECT_EQ(static_cast<std::string_view>(displayName.text()), "PlantOperator");
  EXPECT_TRUE(static_cast<std::string_view>(displayName.locale()).empty());
}

// A configured Role outside namespace 0 without a BrowseName is not created, and the start-up log names
// it. Control: the Role still grants its permissions, to a user its identity rule matches.
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-03-NAMELESS-ROLE-REPORTED, scope=function)
TEST(RoleSetBrowseName, ANamelessConfiguredRoleIsNotCreatedAndIsReported)
{
  const NodeId roleId{1, 42101u};
  auto roleConfiguration = std::make_shared<RoleConfiguration>();
  ASSERT_TRUE(roleConfiguration->add_role(custom_role(roleId, 41)));
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{"nameless-role-user"};
  ASSERT_TRUE(roleConfiguration->add_identity_rule(roleId, std::move(rule)).is_good());
  auto sink = std::make_shared<RoleLogSink>();
  boost::asio::thread_pool pool;
  auto server = create_server(pool.get_executor(), roleConfiguration, sink);
  ServerImplTestAccess access{*server};

  EXPECT_FALSE(access.address_space().try_find_node_sync(roleId).is_good());
  EXPECT_FALSE(contains(role_set_children(access.address_space()), roleId));
  EXPECT_EQ(sink->not_created_warnings(roleId), 1u);

  UserIdentity user;
  user.kind = UserTokenKind::UserName;
  user.userId = "nameless-role-user";
  const auto granted = access.role_configuration()->evaluate_role_ids(user, EndpointSecurityContext{});
  EXPECT_TRUE(contains(granted, roleId)) << "control: the unpublished Role still grants its permissions";
}

// A configured Role whose BrowseName's name another child of RoleSet already has is not created, and the
// log names it: the second of two Roles with one name, and Roles named as the well-known Observer in
// namespace 0 and in namespace 1, since the name is compared as AddRole compares it. Control: the first Role
// with the name is created with it.
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-03-DUPLICATE-REFUSED, scope=function)
TEST(RoleSetBrowseName, ABrowseNameAnotherRoleHasIsRefusedAndReported)
{
  const NodeId firstId{1, 42102u};
  const NodeId secondId{1, 42103u};
  const NodeId observerNamedId{1, 42104u};
  const NodeId observerInOwnNamespaceId{1, 42105u};
  auto roleConfiguration = std::make_shared<RoleConfiguration>();
  ASSERT_TRUE(roleConfiguration->add_role(custom_role(firstId, 42, QualifiedName{1, "Duplicate"})));
  ASSERT_TRUE(roleConfiguration->add_role(custom_role(secondId, 43, QualifiedName{1, "Duplicate"})));
  ASSERT_TRUE(roleConfiguration->add_role(custom_role(observerNamedId, 44, QualifiedName{0, "Observer"})));
  ASSERT_TRUE(
    roleConfiguration->add_role(custom_role(observerInOwnNamespaceId, 45, QualifiedName{1, "Observer"})));
  auto sink = std::make_shared<RoleLogSink>();
  boost::asio::thread_pool pool;
  auto server = create_server(pool.get_executor(), roleConfiguration, sink);
  ServerImplTestAccess access{*server};

  const auto children = role_set_children(access.address_space());
  ASSERT_TRUE(contains(children, firstId));
  auto first = access.address_space().try_find_node_sync(firstId);
  ASSERT_TRUE(first.is_good());
  EXPECT_EQ(first.value().get_browse_name(), (QualifiedName{1, "Duplicate"}));
  EXPECT_EQ(sink->not_created_warnings(firstId), 0u);

  for (const auto& refusedId : {secondId, observerNamedId, observerInOwnNamespaceId})
  {
    EXPECT_FALSE(access.address_space().try_find_node_sync(refusedId).is_good()) << to_string(refusedId);
    EXPECT_FALSE(contains(children, refusedId)) << to_string(refusedId);
    EXPECT_EQ(sink->not_created_warnings(refusedId), 1u) << to_string(refusedId);
    EXPECT_TRUE(access.role_configuration()->get_role(refusedId).has_value()) << to_string(refusedId);
  }
}

// AddRole records the BrowseName it builds from RoleName and NamespaceUri in the RoleDefinition it
// registers. Control: the Role's Object has that BrowseName.
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-03-ADDROLE-RECORDS-NAME, scope=function)
TEST(RoleSetBrowseName, AddRoleRecordsTheBrowseNameItBuilds)
{
  boost::asio::thread_pool pool;
  auto server = create_server(pool.get_executor(), std::make_shared<RoleConfiguration>(), nullptr, true);
  ServerImplTestAccess access{*server};

  const auto result = call_add_role(access.address_space(), "NamedByAddRole", 1);
  ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  ASSERT_EQ(result.value().output_arguments().size(), 1u);
  const auto* roleId = result.value().output_arguments()[0].try_as<NodeId>();
  ASSERT_NE(roleId, nullptr);

  const auto definition = access.role_configuration()->get_role(*roleId);
  ASSERT_TRUE(definition.has_value());
  EXPECT_EQ(definition->browseName, (QualifiedName{1, "NamedByAddRole"}));
  auto role = access.address_space().try_find_node_sync(*roleId);
  ASSERT_TRUE(role.is_good());
  EXPECT_EQ(role.value().get_browse_name(), definition->browseName);
}

// An Object that already exists at a configured Role's NodeId keeps its own BrowseName when the
// population links it under RoleSet. Control: the population reached it, since it is now a child of
// RoleSet.
// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-03-EXISTING-OBJECT-KEEPS-NAME, scope=function)
TEST(RoleSetBrowseName, AnExistingObjectKeepsItsOwnBrowseName)
{
  const NodeId roleId{1, 42110u};
  boost::asio::thread_pool pool;
  auto server = create_server(pool.get_executor(), std::make_shared<RoleConfiguration>());
  ServerImplTestAccess access{*server};

  InitialAttributes attributes;
  attributes.emplace_back(AttributeId::BrowseName, Variant{QualifiedName{1, "OwnName"}});
  attributes.emplace_back(AttributeId::DisplayName, Variant{LocalizedText{String{"OwnName"}}});
  ASSERT_TRUE(
    access.address_space().try_create_node_sync(roleId, NodeClass::Object, std::move(attributes)).is_good());
  ASSERT_FALSE(contains(role_set_children(access.address_space()), roleId));

  ASSERT_TRUE(
    access.role_configuration()->add_role(custom_role(roleId, 45, QualifiedName{1, "ConfiguredName"})));
  populate_role_set(access.address_space(), *access.role_configuration(), std::nullopt);

  EXPECT_TRUE(contains(role_set_children(access.address_space()), roleId));
  auto role = access.address_space().try_find_node_sync(roleId);
  ASSERT_TRUE(role.is_good());
  EXPECT_EQ(role.value().get_browse_name(), (QualifiedName{1, "OwnName"}));
}
