// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_ACCESS_CONTROL_SUPPORT_H
#define UA_TEST_ACCESS_CONTROL_SUPPORT_H

#include "ua_address_space.h"
#include "ua_default_namespace.h"
#include "ua_namespace_array.h"
#include "ua_namespace_authorization.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_role_permission_type.h"
#include "ua_server_authentication.h"
#include "ua_session_security.h"

#include <memory>
#include <stdexcept>
#include <vector>

namespace ua::test_helpers
{

inline NodeId test_access_role_id()
{
  return NodeId{1, uint32_t{0xfffffff0}};
}

inline PermissionType all_permissions()
{
  return PermissionType{uint32_t{0x0001ffff}};
}

inline std::shared_ptr<const AccessIdentity> configure_test_access(AddressSpace addressSpace,
  std::shared_ptr<const server::UserIdentity> user,
  std::shared_ptr<const server::EndpointSecurityContext> endpoint,
  PermissionType namespacePermissions = all_permissions(), std::vector<NodeId> additionalRoles = {})
{
  RolePermissionType permission;
  permission.role_id() = test_access_role_id();
  permission.permissions() = namespacePermissions;
  bool configured = false;
  const auto namespaceCount = addressSpace.namespace_array().get_namespace_array().size();
  for (uint16_t index = 0; index < namespaceCount; ++index)
  {
    auto testNamespace =
      std::dynamic_pointer_cast<default_ns::Namespace>(addressSpace.namespace_array().get_namespace(index));
    if (!testNamespace)
      continue;
    testNamespace->set_namespace_defaults(std::vector<RolePermissionType>{permission}, std::nullopt);
    configured = true;
  }
  if (!configured)
    throw std::logic_error{"test address space has no configurable default namespace"};

  std::vector<NodeId> grantedRoles{test_access_role_id()};
  grantedRoles.insert(grantedRoles.end(), additionalRoles.begin(), additionalRoles.end());
  return std::make_shared<AccessIdentity>(AccessIdentityKey{1},
    std::move(grantedRoles),
    std::move(user),
    std::move(endpoint),
    String{"urn:test:client"});
}

/// Grants the nodes owned by @p namespaceIndex to the well-known Roles an ordinary test client holds.
///
/// With the Role model engaged, a namespace that has declared no permissions publishes an ENGAGED, EMPTY
/// default and hides every undecorated node it owns. A test that registers its own namespace, creates nodes
/// in it and then browses as a real client therefore sees nothing at all - no error at the top of the walk,
/// just an empty result, because each node is individually refused. That silence reads as "the server does
/// not publish this", which is how an absence assertion can pass while its own control fails.
///
/// This is the per-namespace form of `grant_fixture_namespace_permissions` in compliance_helpers.h; call it
/// with the index `add_namespace_sync` just returned. A fixture whose SUBJECT is a denial must NOT call it -
/// it would grant away the thing under test.
inline void grant_namespace_to_test_client(AddressSpace addressSpace, uint16_t namespaceIndex,
  std::vector<NodeId> roles = {NodeId{ObjectId::WellKnownRole_Anonymous},
    NodeId{ObjectId::WellKnownRole_AuthenticatedUser},
    NodeId{ObjectId::WellKnownRole_SecurityAdmin}})
{
  auto owned = std::dynamic_pointer_cast<default_ns::Namespace>(
    addressSpace.namespace_array().get_namespace(namespaceIndex));
  if (!owned)
    throw std::logic_error{"namespace index does not name a writable default namespace"};

  std::vector<RolePermissionType> grants;
  grants.reserve(roles.size());
  for (auto& role : roles)
  {
    RolePermissionType grant;
    grant.role_id() = std::move(role);
    grant.permissions() = all_permissions();
    grants.push_back(std::move(grant));
  }
  owned->set_namespace_defaults(std::move(grants), std::nullopt);
}

inline void set_test_node_permissions(NodeAccessor& node, PermissionType permissions)
{
  RolePermissionType permission;
  permission.role_id() = test_access_role_id();
  permission.permissions() = permissions;
  node.set_role_permissions(std::vector<RolePermissionType>{permission});
}

class TestSessionSecurityContext final : public server::SessionSecurityContext
{
public:
  explicit TestSessionSecurityContext(AddressSpace addressSpace)
  {
    auto endpoint = std::make_shared<server::EndpointSecurityContext>();
    endpoint->endpointPolicyId = "Test/None";
    endpoint->messageSecurityMode = MessageSecurityMode::None;
    endpoint->securityPolicyId = SecurityPolicyId::None;
    mEndpoint = std::move(endpoint);

    auto user = std::make_shared<server::UserIdentity>();
    user->userId = "test";
    user->displayName = "Test";
    user->kind = server::UserTokenKind::Anonymous;
    mUser = std::move(user);
    mIdentity = configure_test_access(std::move(addressSpace), mUser, mEndpoint);
  }

  NodeId session_id() const override
  {
    return NodeId{1, uint32_t{1}};
  }

  std::shared_ptr<const server::EndpointSecurityContext> endpoint_security() const override
  {
    return mEndpoint;
  }

  std::shared_ptr<const server::UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return mIdentity;
  }

private:
  std::shared_ptr<const server::EndpointSecurityContext> mEndpoint;
  std::shared_ptr<const server::UserIdentity> mUser;
  std::shared_ptr<const AccessIdentity> mIdentity;
};

}  // namespace ua::test_helpers

#endif  // UA_TEST_ACCESS_CONTROL_SUPPORT_H
