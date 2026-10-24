// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Shared fixture support for the NodeManagement pin tests.
//
// Provides a minimal `NodeManagementPinSessionInfo` that satisfies both
// SessionInfo and SessionSecurityContext, with canonical per-node permissions
// and per-test access to the ServerConfig (for limit overrides).
//
// The session does NOT publish an EventBus - audit-event capture pins are
// flagged as INFRA GAP in this PR (see runbook section 4.0 TODO + the AN-K/AR-K
// pin notes); a real EventBus listener is required to observe audit emission
// because emit_node_mgmt_audit() static_casts the EventSink to EventBus and
// gates on `has_event_interest()`.

#ifndef UA_TEST_BEHAVIOUR_PINS_PHASE_4_5I_NODE_MANAGEMENT_PIN_FIXTURE_H
#define UA_TEST_BEHAVIOUR_PINS_PHASE_4_5I_NODE_MANAGEMENT_PIN_FIXTURE_H

#include <chrono>
#include <future>
#include <memory>
#include <string>

#include "ua_address_space.h"
#include "access_control_test_support.h"
#include "ua_application_configuration.h"
#include "ua_default_namespace.h"
#include "ua_diagnostic_policy.h"
#include "ua_diagnostic_to_error_detail.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_node_accessor.h"
#include "ua_server_configuration.h"
#include "ua_server_session_info.h"

#include "security/ua_server_authentication.h"
#include "ua_session_security.h"

namespace ua::test::behaviour_pins
{

inline const ua::NodeId nodeManagementPinObjectTypeId{1, 65000u};
inline const ua::NodeId nodeManagementPinReferenceTypeId{1, 65001u};

class NodeManagementPinSessionInfo final : public ua::server::SessionInfo,
                                           public ua::server::SessionSecurityContext
{
public:
  explicit NodeManagementPinSessionInfo(boost::asio::any_io_executor executor,
    ua::PermissionType initialNamespacePermissions = ua::test_helpers::all_permissions())
    : mExecutor(executor),
      mAppCfg(std::make_shared<const ua::ApplicationConfig>(ua::ApplicationConfig::load_default())),
      mAddressSpace(ua::AddressSpace::create("urn:test", mExecutor))
  {
    auto security = std::make_shared<ua::server::EndpointSecurityContext>();
    security->endpointPolicyId = "L/None";
    security->messageSecurityMode = ua::MessageSecurityMode::None;
    security->securityPolicyId = ua::SecurityPolicyId::None;
    mSecurity = std::move(security);

    auto user = std::make_shared<ua::server::UserIdentity>();
    user->userId = "anonymous";
    user->displayName = "Anonymous";
    user->kind = ua::server::UserTokenKind::Anonymous;
    mUser = std::move(user);

    ensure_authz_node(nodeManagementPinObjectTypeId, ua::NodeClass::ObjectType);
    ensure_authz_node(nodeManagementPinReferenceTypeId, ua::NodeClass::ReferenceType);
    mAccessIdentity =
      ua::test_helpers::configure_test_access(mAddressSpace, mUser, mSecurity, initialNamespacePermissions);
  }

  // --- SessionInfo ----------------------------------------------------------

  boost::asio::any_io_executor executor() const
  {
    return mExecutor;
  }

  ua::AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ua::ApplicationConfig& configuration() const override
  {
    return *mAppCfg;
  }

  const ua::server::ServerConfig& server_configuration() const override
  {
    return serverCfg;
  }

  ua::server::DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return ua::server::detail::make_diagnostic_security_context(
      *mSecurity, *mUser, serverCfg.diagnosticPolicy);
  }

  ua::Logger logger() const override
  {
    return {};
  }

  // --- SessionSecurityContext -----------------------------------------------

  ua::NodeId session_id() const override
  {
    return ua::NodeId{1, 1u};
  }

  std::shared_ptr<const ua::server::EndpointSecurityContext> endpoint_security() const override
  {
    return mSecurity;
  }

  std::shared_ptr<const ua::server::UserIdentity> user_identity() const override
  {
    return mUser;
  }

  std::shared_ptr<const ua::AccessIdentity> access_identity() const override
  {
    return mAccessIdentity;
  }

  // --- Test access (used by individual pins to override defaults) -----------

  ua::server::ServerConfig serverCfg;

  void set_node_permissions(const ua::NodeId& nodeId, ua::PermissionType permissions)
  {
    auto node = mAddressSpace.find_node_sync(nodeId);
    ua::test_helpers::set_test_node_permissions(node, permissions);
  }

  void ensure_authz_namespace(
    uint16_t namespaceIndex, ua::PermissionType permissions = ua::test_helpers::all_permissions())
  {
    while (mAddressSpace.namespace_array().get_namespace(namespaceIndex) == nullptr)
    {
      const auto index = mAddressSpace.namespace_array().get_namespace_array().size();
      auto testNamespace =
        ua::default_ns::Namespace::create("urn:test:ns:" + std::to_string(index), mExecutor);
      ua::PermissionType newNamespacePermissions = ua::test_helpers::all_permissions();
      if (index == namespaceIndex)
        newNamespacePermissions = permissions;
      ua::RolePermissionType permission;
      permission.role_id() = ua::test_helpers::test_access_role_id();
      permission.permissions() = newNamespacePermissions;
      testNamespace->set_namespace_defaults(
        std::vector<ua::RolePermissionType>{std::move(permission)}, std::nullopt);
      mAddressSpace.add_namespace_sync(testNamespace);
    }
  }

  /// Pre-create the authz target node in the address space (extending the
  /// namespace array as needed). The post-Authorizer-redesign NodeManagement
  /// flow resolves the authz NodeId via `find_node_async` before calling
  /// `authorize_operation`, so test parents/sources/targets must exist as
  /// real nodes; otherwise `BadNodeIdUnknown` short-circuits the flow.
  void ensure_authz_node(const ua::NodeId& nodeId, ua::NodeClass nodeClass = ua::NodeClass::Object)
  {
    ensure_authz_namespace(nodeId.namespace_index());
    auto created = mAddressSpace.try_create_node_sync(nodeId, nodeClass, {});
    if (created)
      ua::test_helpers::set_test_node_permissions(created.value(), ua::test_helpers::all_permissions());
  }

private:
  boost::asio::any_io_executor mExecutor;
  std::shared_ptr<const ua::ApplicationConfig> mAppCfg;
  ua::AddressSpace mAddressSpace;
  std::shared_ptr<const ua::server::EndpointSecurityContext> mSecurity;
  std::shared_ptr<const ua::server::UserIdentity> mUser;
  std::shared_ptr<const ua::AccessIdentity> mAccessIdentity;
};

}  // namespace ua::test::behaviour_pins

#endif  // !UA_TEST_BEHAVIOUR_PINS_PHASE_4_5I_NODE_MANAGEMENT_PIN_FIXTURE_H
