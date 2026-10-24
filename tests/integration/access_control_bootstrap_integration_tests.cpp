// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// The bootstrap floor of the access-control design section 7.4, over the wire.
///
/// Of the 557 Nodes the shipped NodeSet decorates, only five Role NodeIds ever appear, and
/// `NamespaceArray` and `ServerArray` name three of the nine well-known Roles. Enforcing the NodeSet as
/// published therefore locks the other six out of the read every client performs first.
///
/// The Anonymous Role is what conceals that today: `seed_well_known_roles` gives it both the Anonymous
/// and the AuthenticatedUser identity rules, so every Session inherits its 195-Node grant as a floor.
/// Every fixture here pre-registers the Anonymous slot with no identity rule, which is what makes the
/// arms measure the Role under test rather than that floor.

#include <gtest/gtest.h>

#include "helpers/role_based_security_fixture.h"
#include "helpers/sanitizer_budget.h"

#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_node_accessor.h"
#include "ua_permission_type.h"
#include "ua_read_value_id.h"
#include "ua_role_permission_type.h"
#include "ua_session_attribute_services.h"
#include "ua_status.h"
#include "ua_timestamps_to_return.h"
#include "ua_to_string.h"
#include "ua_variable_id.h"
#include "ua_well_known_role_permissions.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace ua;
using namespace ua::server;

namespace
{

/// The Nodes 7.4 names: the Server Object and the three Variables under it a client reads before it
/// can address anything else.
const std::vector<NodeId>& bootstrap_nodes()
{
  static const std::vector<NodeId> nodes{NodeId{ObjectId::Server},
    NodeId{VariableId::Server_ServerArray},
    NodeId{VariableId::Server_NamespaceArray},
    NodeId{VariableId::Server_ServerStatus}};
  return nodes;
}

const std::vector<NodeId>& history_capability_variables()
{
  static const std::vector<NodeId> nodes{
    NodeId{VariableId::HistoryServerCapabilities_AccessHistoryDataCapability},
    NodeId{VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability},
    NodeId{VariableId::HistoryServerCapabilities_MaxReturnDataValues},
    NodeId{VariableId::HistoryServerCapabilities_MaxReturnEventValues},
    NodeId{VariableId::HistoryServerCapabilities_InsertDataCapability},
    NodeId{VariableId::HistoryServerCapabilities_ReplaceDataCapability},
    NodeId{VariableId::HistoryServerCapabilities_UpdateDataCapability},
    NodeId{VariableId::HistoryServerCapabilities_DeleteRawCapability},
    NodeId{VariableId::HistoryServerCapabilities_DeleteAtTimeCapability},
    NodeId{VariableId::HistoryServerCapabilities_InsertEventCapability},
    NodeId{VariableId::HistoryServerCapabilities_ReplaceEventCapability},
    NodeId{VariableId::HistoryServerCapabilities_UpdateEventCapability},
    NodeId{VariableId::HistoryServerCapabilities_DeleteEventCapability},
    NodeId{VariableId::HistoryServerCapabilities_InsertAnnotationCapability},
    NodeId{VariableId::HistoryServerCapabilities_ServerTimestampSupported}};
  return nodes;
}

const std::vector<NodeId>& history_capability_surface()
{
  static const std::vector<NodeId> nodes = []
  {
    std::vector<NodeId> result{NodeId{ObjectId::HistoryServerCapabilities},
      NodeId{ObjectId::HistoryServerCapabilities_AggregateFunctions}};
    result.insert(result.end(), history_capability_variables().begin(), history_capability_variables().end());
    return result;
  }();
  return nodes;
}

/// Base for both arms of the control. Registers the Anonymous Role with no identity rule so it grants
/// nothing, then leaves the subclass to grant exactly one other Role.
class BootstrapFloorBase : public ComplianceRoleBasedSecurity
{
protected:
  /// Neutralise the three Roles the SDK self-seeds with an identity rule - Anonymous (which takes both
  /// the Anonymous and the AuthenticatedUser rule), AuthenticatedUser, and TrustedApplication. Left
  /// alone, every Session here would hold three Roles rather than the one under test, and an arm that
  /// removed one grant would still be carried by the other two.
  ///
  /// Registering the slot is what makes `seed_well_known_roles` skip it; the empty `identities` is
  /// then what stops any Session being placed in it.
  static void register_self_seeding_roles_without_identities(RoleConfiguration& config)
  {
    const std::array<std::pair<ObjectId, uint8_t>, 3> selfSeeding{{{ObjectId::WellKnownRole_Anonymous, 0},
      {ObjectId::WellKnownRole_AuthenticatedUser, 1},
      {ObjectId::WellKnownRole_TrustedApplication, 8}}};
    for (const auto& [role, roleBit] : selfSeeding)
    {
      RoleConfiguration::RoleDefinition definition;
      definition.roleId = NodeId{role};
      definition.roleBit = roleBit;
      ASSERT_TRUE(config.add_role(std::move(definition))) << "self-seeding slot must register";
    }
  }

  static void grant_role_to_user(
    RoleConfiguration& config, ObjectId role, uint8_t roleBit, const std::string& userId)
  {
    RoleConfiguration::RoleDefinition definition;
    definition.roleId = NodeId{role};
    definition.roleBit = roleBit;
    ASSERT_TRUE(config.add_role(std::move(definition))) << "Role slot must register";
    IdentityMappingRuleType rule;
    rule.criteria_type() = IdentityCriteriaType::UserName;
    rule.criteria() = String{userId};
    const auto result = config.add_identity_rule(NodeId{role}, std::move(rule));
    ASSERT_TRUE(result.is_good()) << "UserName rule must register: " << result.status_code().value();
  }

  /// Read the Value of every bootstrap Node in one request and return the per-item statuses.
  std::vector<StatusCode> read_bootstrap(ua::client::Session& session)
  {
    ReadRequest request;
    request.timestamps_to_return() = TimestampsToReturn::Neither;
    for (const auto& nodeId : bootstrap_nodes())
    {
      ReadValueId item;
      item.node_id() = nodeId;
      // The Server Object has no Value, so every Node is read for an Attribute it actually has and a
      // refusal cannot be mistaken for Bad_AttributeIdInvalid.
      item.attribute_id() = static_cast<uint32_t>(
        nodeId == NodeId{ObjectId::Server} ? AttributeId::BrowseName : AttributeId::Value);
      request.nodes_to_read().push_back(std::move(item));
    }

    auto response = session.attributes().read_sync(std::move(request));
    EXPECT_TRUE(response.response_header().service_result().is_good())
      << "bootstrap Read service result: " << response.response_header().service_result().value();

    std::vector<StatusCode> statuses;
    statuses.reserve(response.results().size());
    for (const auto& result : response.results())
    {
      // DataValue::status() is engaged only when the server sent one; an absent status is Good.
      statuses.push_back(result.status().value_or(StatusCode{}));
    }
    return statuses;
  }
};

/// A Session holding Observer and nothing else. The NodeSet names Observer on none of the bootstrap
/// Nodes, so this is the arm the floor exists for.
class ComplianceAccessControlObserver : public BootstrapFloorBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    register_self_seeding_roles_without_identities(config);
    grant_role_to_user(config, ObjectId::WellKnownRole_Observer, 2, "observer");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "observer", std::unordered_map<std::string, std::string>{});
  }
};

/// The control's other arm: a Session holding SecurityAdmin, which the NodeSet does name on the
/// bootstrap Nodes. It must bootstrap too, or the arm above proves nothing about the floor.
class ComplianceAccessControlSecurityAdmin : public BootstrapFloorBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    register_self_seeding_roles_without_identities(config);
    grant_role_to_user(config, ObjectId::WellKnownRole_SecurityAdmin, 7, "secadmin");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "secadmin", std::unordered_map<std::string, std::string>{});
  }
};

/// The negative arm. Same Session as the positive Observer arm, but the floor is taken back off the
/// bootstrap Nodes after start: each one's `RolePermissions` array has its Observer entry removed and
/// is written back, restoring exactly the state the NodeSet publishes for that Role.
///
/// Removing the entry rather than writing a literal array keeps the arm honest in two ways. It cannot
/// drift from whatever the shipped NodeSet or the floor decide to grant the other eight Roles, and it
/// cannot pass by refusing for some unrelated reason: the only difference between this fixture and the
/// one above is the presence of the entry the floor supplies.
class ComplianceAccessControlObserverWithoutFloor : public ComplianceAccessControlObserver
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    const NodeId observerRole{ObjectId::WellKnownRole_Observer};
    for (const auto& nodeId : bootstrap_nodes())
    {
      auto node = addressSpace.find_node_sync(nodeId);
      auto permissions = node.get_role_permissions();
      ASSERT_TRUE(permissions.has_value())
        << to_string(nodeId) << " carries no RolePermissions, so the floor was never applied";

      const auto removed = std::remove_if(permissions->begin(),
        permissions->end(),
        [&observerRole](const RolePermissionType& entry) { return entry.role_id() == observerRole; });
      ASSERT_NE(removed, permissions->end())
        << to_string(nodeId) << " names no Observer entry, so removing it proves nothing";
      permissions->erase(removed, permissions->end());

      node.set_role_permissions(*permissions);

      // Read back: a setter that silently did nothing would leave the arm asserting a refusal that
      // never had a reason to happen.
      auto written = addressSpace.find_node_sync(nodeId).get_role_permissions();
      ASSERT_TRUE(written.has_value()) << to_string(nodeId) << " lost its array entirely";
      EXPECT_EQ(
        std::count_if(written->begin(),
          written->end(),
          [&observerRole](const RolePermissionType& entry) { return entry.role_id() == observerRole; }),
        0)
        << to_string(nodeId) << " still names Observer after the write";
    }
  }
};

/// Same Observer-only Session as the positive arm, with the history-capability surface given namespace 0's
/// DefaultRolePermissions explicitly, without Observer's entry. The surface has no array of its own and takes
/// that default, so a refusal can only come from the ordinary per-node decision the positive arm passed.
/// Bootstrap remains intact.
class ComplianceAccessControlObserverWithoutHistoryCapabilityEntry : public ComplianceAccessControlObserver
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    const NodeId observerRole{ObjectId::WellKnownRole_Observer};
    for (const auto& nodeId : history_capability_surface())
    {
      auto node = addressSpace.find_node_sync(nodeId);
      ASSERT_FALSE(node.get_role_permissions().has_value())
        << to_string(nodeId) << " has an array of its own, where it should take the namespace default";

      auto permissions = server::well_known_role_default_permissions(server::well_known_roles());
      const auto removed = std::remove_if(permissions.begin(),
        permissions.end(),
        [&observerRole](const RolePermissionType& entry) { return entry.role_id() == observerRole; });
      ASSERT_NE(removed, permissions.end()) << "the namespace default names no Observer entry";
      permissions.erase(removed, permissions.end());
      node.set_role_permissions(permissions);
    }
  }
};

class ComplianceAccessIdentityLimit : public ComplianceRoleBasedSecurity
{
protected:
  void customize_server_configuration(ServerConfig& config) override
  {
    config.maxAccessIdentities = 1;
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "identity-limit-user", std::unordered_map<std::string, std::string>{});
  }
};

}  // namespace

// @relation(AC-SVR-AUTHZ-013-OBSERVER-CAN-BOOTSTRAP, scope=function)
TEST_F(ComplianceAccessControlObserver, SingleWellKnownRoleCompletesBootstrap)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ObserverBootstrap");

  const auto statuses = read_bootstrap(session);
  ASSERT_EQ(statuses.size(), bootstrap_nodes().size());
  for (std::size_t index = 0; index < statuses.size(); ++index)
  {
    EXPECT_TRUE(statuses[index].is_good())
      << "Observer cannot read " << to_string(bootstrap_nodes()[index]) << ": " << statuses[index].value();
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// The control's other arm.
// @relation(AC-SVR-AUTHZ-013-OBSERVER-CAN-BOOTSTRAP, scope=function)
TEST_F(ComplianceAccessControlSecurityAdmin, SingleWellKnownRoleCompletesBootstrap)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "SecurityAdminBootstrap");

  const auto statuses = read_bootstrap(session);
  ASSERT_EQ(statuses.size(), bootstrap_nodes().size());
  for (std::size_t index = 0; index < statuses.size(); ++index)
  {
    EXPECT_TRUE(statuses[index].is_good())
      << "SecurityAdmin cannot read " << to_string(bootstrap_nodes()[index]) << ": "
      << statuses[index].value();
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-AUTHZ-013-HISTORY-CAPABILITIES-READABLE, scope=function)
TEST_F(ComplianceAccessControlObserver, SingleWellKnownRoleReadsHistoryCapabilities)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ObserverHistoryCaps");

  ReadRequest request;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  for (const auto& nodeId : history_capability_variables())
  {
    ReadValueId item;
    item.node_id() = nodeId;
    item.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    request.nodes_to_read().push_back(std::move(item));
  }
  const auto response = session.attributes().read_sync(std::move(request));
  ASSERT_EQ(response.results().size(), history_capability_variables().size());
  for (std::size_t index = 0; index < response.results().size(); ++index)
  {
    const auto status = response.results()[index].status().value_or(StatusCode{});
    EXPECT_TRUE(status.is_good()) << "Observer cannot read "
                                  << to_string(history_capability_variables()[index]) << ": "
                                  << status.value();
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-AUTHZ-013-HISTORY-CAPABILITIES-READABLE, scope=function)
TEST_F(ComplianceAccessControlObserverWithoutHistoryCapabilityEntry,
  HistoryCapabilitiesAreRefusedWhenObserversEntryIsRemoved)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ObserverNoHistoryCaps");

  ReadRequest request;
  request.timestamps_to_return() = TimestampsToReturn::Neither;
  for (const auto& nodeId : history_capability_variables())
  {
    ReadValueId item;
    item.node_id() = nodeId;
    item.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    request.nodes_to_read().push_back(std::move(item));
  }
  const auto response = session.attributes().read_sync(std::move(request));
  ASSERT_EQ(response.results().size(), history_capability_variables().size());
  for (std::size_t index = 0; index < response.results().size(); ++index)
  {
    const auto status = response.results()[index].status().value_or(StatusCode{});
    EXPECT_EQ(status, Status::BadUserAccessDenied)
      << "Observer still reads " << to_string(history_capability_variables()[index])
      << " after only its entry was removed";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// The negative arm of the same criterion: with the floor's Observer entry removed, the Session that
// bootstrapped above is refused. Without this the positive arms cannot distinguish a working floor
// from a server that authorizes nothing.
// @relation(AC-SVR-AUTHZ-013-OBSERVER-CAN-BOOTSTRAP, scope=function)
TEST_F(ComplianceAccessControlObserverWithoutFloor, BootstrapIsRefusedWhenTheFloorIsRemoved)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ObserverNoFloor");

  const auto statuses = read_bootstrap(session);
  ASSERT_EQ(statuses.size(), bootstrap_nodes().size());
  for (std::size_t index = 0; index < statuses.size(); ++index)
  {
    EXPECT_EQ(statuses[index], Status::BadUserAccessDenied)
      << "Observer still reads " << to_string(bootstrap_nodes()[index])
      << " with the floor removed, so the floor is not what granted it";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-AUTHZ-021-LIVE-POPULATION-IS-BOUNDED, scope=function)
TEST_F(ComplianceAccessIdentityLimit, DistinctActivationAtConfiguredCapIsRefusedUntilRelease)
{
  auto encryptedChannel = open_channel(MessageSecurityMode::SignAndEncrypt);
  auto encryptedSession = encryptedChannel.create_session_sync({.sessionName = "IdentityLimitEncrypted"});
  ASSERT_TRUE(encryptedSession.try_activate_sync().is_good());

  auto noneChannel = open_channel(MessageSecurityMode::None);
  auto noneSession = noneChannel.create_session_sync({.sessionName = "IdentityLimitNone"});
  auto refused = noneSession.try_activate_sync();
  ASSERT_TRUE(refused.is_bad());
  EXPECT_EQ(refused.status_code(), Status::BadTooManySessions);
  EXPECT_NE(refused.shared_detail(), nullptr);

  ASSERT_TRUE(encryptedSession.try_close_sync().is_good());

  // Closing a Session and releasing its identity's capacity are two instants, not one: the release
  // runs on the server's own strand once the CloseSession response is already on the wire. So poll
  // the condition this asserts instead of the instant before it - bounded, which keeps the
  // assertion intact: a server that never releases capacity still fails here.
  StatusCode lastRefusal{Status::Good};
  bool released = false;
  const auto deadline =
    std::chrono::steady_clock::now() + ua::test_utils::scaled(std::chrono::milliseconds{2000});
  do
  {
    auto retrySession = noneChannel.create_session_sync({.sessionName = "IdentityLimitNoneRetry"});
    const auto activated = retrySession.try_activate_sync();
    lastRefusal = activated.status_code();
    released = activated.is_good();
    (void)retrySession.try_close_sync();
    if (released)
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{25});
  } while (std::chrono::steady_clock::now() < deadline);

  ASSERT_TRUE(released) << "closing the only live identity must release capacity for a distinct "
                           "activation; the last attempt was refused with "
                        << to_string(lastRefusal);

  (void)noneChannel.try_close_sync();
  (void)encryptedChannel.try_close_sync();
}
