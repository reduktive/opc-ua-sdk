// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_ROLE_BASED_SECURITY_FIXTURE_H
#define UA_TEST_ROLE_BASED_SECURITY_FIXTURE_H

/// Fixture for end-to-end RBAC integration tests against a Part-18-wired
/// server. Inherits the secured-server scaffolding from `ComplianceSecured`
/// (3 endpoints - None / Sign / SignAndEncrypt - both certs already
/// installed in the trust list) and layers on:
///
///   1. `ServerComponents::roleConfiguration` set to trigger Part-18
///      RoleSet wiring and canonical access-identity grants at server startup.
///   2. `customize_role_configuration(RoleConfiguration&)` - runs **before**
///      `Server::create` so `seed_well_known_roles` sees pre-existing roles
///      and skips them, and `populate_role_set` mirrors the customised
///      state into the NS0 RoleSet at startup.
///   3. `customize_address_space(AddressSpace&)` - runs **after**
///      `Server::create`. Subclasses add a per-test namespace + test
///      Variables (typically with explicit `RolePermissions`) to gate
///      Reads on specific role grants.
///   4. `open_channel(mode, policy)` to vary the SecureChannel security
///      mode across test cases.
///   5. `read_role_identities(session, identitiesNodeId)` to read the
///      `Identities` Property of a Role Object over the wire and decode it
///      into a vector of `IdentityMappingRuleType` values - the canonical
///      observable for the predicate-engine format / canonicalisation /
///      dual-rule invariants. The reader must hold `SecurityAdmin` /
///      `ConfigureAdmin` (Part 18 section 4.4.1 gates the RoleSet surface) and use
///      a SignAndEncrypt channel (`EncryptionRequired` AccessRestriction).
///
/// This fixture is the preferred entry point for any RBAC mirror under
/// tests/integration/.
/// File-local fixtures should be added here rather than re-rolled in test
/// files.

#include "../compliance_helpers.h"

#include "ua_access_level_type.h"
#include "ua_built_in_authenticators.h"
#include "ua_attribute_id.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_role_configuration.h"
#include "ua_role_permission_type.h"
#include "ua_server_components.h"
#include "ua_session_attribute_services.h"
#include "ua_variable_id.h"

#include "matchers.h"
#include "requests.h"

#include <gtest/gtest.h>

#include <memory>
#include <unordered_map>
#include <vector>

/// Test-only authenticator that returns a fixed `UserIdentity` with a
/// caller-supplied claim map. Used by integration tests that need to
/// inject `thumbprint` / `x509:subject` / etc. claims that the production
/// authentication path would source from the user's X509 identity token -
/// the SDK does not yet auto-populate those claims for X509 user tokens,
/// so the test injects them directly to exercise the matching path.
///
/// All sessions authenticated by this authenticator receive the same
/// identity; sessions on the same fixture see the same claims.
class ClaimInjectingAuthenticator : public ua::server::UserAuthenticator
{
public:
  ClaimInjectingAuthenticator(
    ua::server::UserTokenKind kind, std::string userId, std::unordered_map<std::string, std::string> claims)
    : mKind(kind), mUserId(std::move(userId)), mClaims(std::move(claims))
  {}

  void authenticate_async(ua::server::AuthnRequest, ua::server::AuthnComplete completion) noexcept override
  {
    ua::server::UserIdentity user;
    user.kind = mKind;
    user.userId = mUserId;
    user.displayName = mUserId.empty() ? std::string{"Anonymous"} : mUserId;
    user.claims = mClaims;
    completion(ua::server::make_authn_success(std::move(user)));
  }

private:
  ua::server::UserTokenKind mKind;
  std::string mUserId;
  std::unordered_map<std::string, std::string> mClaims;
};

class ComplianceRoleBasedSecurity : public ComplianceSecured
{
public:
  /// Subclasses customise the RoleConfiguration before the server is
  /// constructed. Called from `configure_components` which itself runs
  /// from `ComplianceSecured::SetUp()` before `Server::create`.
  ///
  /// Override and pre-populate well-known role definitions (so
  /// `seed_well_known_roles` skips them) or add custom roles.
  virtual void customize_role_configuration(ua::server::RoleConfiguration& /*config*/)
  {}

  /// Subclasses customise the address space after the server is up.
  /// Called from `ComplianceRoleBasedSecurity::SetUp()` immediately after
  /// `ComplianceSecured::SetUp()` returns. Typical use: create a test
  /// namespace, set its standard Role-model defaults (via
  /// `default_ns::Namespace::set_namespace_defaults`), and add
  /// per-test Variables with explicit `RolePermissions` so Reads pin role
  /// grants over the wire.
  virtual void customize_address_space(ua::AddressSpace& /*addressSpace*/)
  {}

  void SetUp() override
  {
    ComplianceSecured::SetUp();
    auto addressSpace = mServer->address_space();
    customize_address_space(addressSpace);
  }

  /// Align the client's `ApplicationConfig.mApplicationUri` with
  /// the client cert SAN URI so `ClientDescription.application_uri`
  /// captured at `CreateSession` (and surfaced to the predicate engine
  /// as `EndpointSecurityContext::clientApplicationUri`) matches the
  /// cert - the spec-mandated equality (Part 4 section 5.4.2) that
  /// SECADMIN-029 / SECADMIN-032 tests rely on.
  void configure_client_application(ua::ApplicationConfig& appCfg) override
  {
    appCfg.application_description_part().applicationUri = "urn:test:compliance:client";
  }

  /// Subclasses override to supply a custom authenticator. Default returns
  /// `AnonymousAuthenticator`. Tests that need to inject claims (for
  /// Thumbprint / X509Subject / Role / GroupId criteria match testing)
  /// return a `ClaimInjectingAuthenticator`.
  virtual std::shared_ptr<ua::server::UserAuthenticator> make_authenticator()
  {
    return std::make_shared<ua::server::AnonymousAuthenticator>();
  }

  void configure_components(ua::server::ServerComponents& components) override
  {
    roleConfiguration = std::make_shared<ua::server::RoleConfiguration>();
    customize_role_configuration(*roleConfiguration);
    components.authenticator = make_authenticator();
    components.roleConfiguration = roleConfiguration;
  }

  /// Enable the Q-RBAC method-management surface (AddRole / RemoveRole +
  /// the per-role Add/Remove Identity/Application/Endpoint handlers). The
  /// SDK only installs the Method Call handlers when
  /// `roleManagementEnabled` is true (`ServerImpl::wire_authorizer`), so
  /// every Phase-P2 management-Method mirror needs this. Subclasses that
  /// need further server-config tweaks (e.g. a restricted
  /// `wellKnownRoles` selection) override `customize_server_configuration`
  /// rather than this method.
  void configure_server_create_config(ua::server::CreateConfig& cfg) override
  {
    cfg.server.roleManagementEnabled = true;
    customize_server_configuration(cfg.server);
  }

  /// Subclasses customise the `ServerConfig` before the server is
  /// created (e.g. set `wellKnownRoles` to leave a well-known Role
  /// unseeded for the AddRole well-known-NodeId-reuse mirror). Runs after
  /// `roleManagementEnabled` has been set to true.
  virtual void customize_server_configuration(ua::server::ServerConfig& /*serverConfig*/)
  {}

  /// Open a SecureChannel against the fixture's secured server with the
  /// requested security mode/policy. Defaults: Basic256Sha256 for any
  /// non-None mode (matches the endpoints `ComplianceSecured` installs).
  ua::client::SecureChannel open_channel(
    ua::MessageSecurityMode mode, ua::SecurityPolicyId policy = ua::SecurityPolicyId::Basic256Sha256)
  {
    ua::client::CoreClient::OpenChannelConfig cfg;
    cfg.endpointUrl = mEndpointUrl;
    cfg.securityMode = mode;
    cfg.securityPolicyId = (mode == ua::MessageSecurityMode::None) ? ua::SecurityPolicyId::None : policy;
    if (mode != ua::MessageSecurityMode::None)
      cfg.serverCertificate = mServerCert;
    return mClient->core().open_channel_sync(std::move(cfg));
  }

  /// Open channel + create session + activate in one shot.
  std::pair<ua::client::SecureChannel, ua::client::Session> open_session(
    ua::MessageSecurityMode mode, const std::string& sessionName)
  {
    auto channel = open_channel(mode);
    auto session = channel.create_session_sync({.sessionName = sessionName});
    session.activate_sync();
    return {std::move(channel), std::move(session)};
  }

  /// Map an authenticated `UserName` identity to the well-known
  /// `SecurityAdmin` Role (canonical bit 7), so a session that
  /// authenticates as `userId` resolves to SecurityAdmin and clears the
  /// Part-18 section 4.2/section 4.4 management-Method admin gate (`is_admin_caller`
  /// checks the SecurityAdmin bit).
  ///
  /// Realistic by construction: SecurityAdmin - the GDS cert-push admin
  /// role - is reached only by an *authenticated* credential, never by an
  /// Anonymous session. A test that needs both an admin and a non-admin
  /// session uses an admin fixture whose authenticator presents `userId`
  /// and a separate non-admin fixture left on the default Anonymous
  /// authenticator. Pre-registering the slot makes `seed_well_known_roles`
  /// leave SecurityAdmin alone and keep this UserName rule.
  ///
  /// Pairs with `make_authenticator()` returning
  /// `ClaimInjectingAuthenticator(UserTokenKind::UserName, userId, {})`.
  static void grant_security_admin_to_user(ua::server::RoleConfiguration& config, const std::string& userId)
  {
    ua::server::RoleConfiguration::RoleDefinition def;
    def.roleId = ua::NodeId{0, static_cast<uint32_t>(ua::ObjectId::WellKnownRole_SecurityAdmin)};
    def.roleBit = 7;
    ASSERT_TRUE(config.add_role(std::move(def))) << "SecurityAdmin slot must register";
    ua::IdentityMappingRuleType rule;
    rule.criteria_type() = ua::IdentityCriteriaType::UserName;
    rule.criteria() = ua::String{userId};
    auto result = config.add_identity_rule(
      ua::NodeId{0, static_cast<uint32_t>(ua::ObjectId::WellKnownRole_SecurityAdmin)}, std::move(rule));
    ASSERT_TRUE(result.is_good()) << "SecurityAdmin UserName rule must register: "
                                  << result.status_code().value();
  }

  /// Construct a `RolePermissionType` granting the given role the given
  /// permission bits. Used by tests setting per-Node RolePermissions on
  /// test Variables.
  static ua::RolePermissionType make_role_permission(
    const ua::NodeId& roleId, std::initializer_list<ua::PermissionType::Bit> bits)
  {
    ua::RolePermissionType entry;
    entry.role_id() = roleId;
    entry.permissions() = ua::PermissionType{bits};
    return entry;
  }

  /// Create a test namespace, add it to the address space, and return the
  /// allocated namespace index. The fixture caller uses this index to
  /// construct test-NodeIds (e.g. `NodeId{index, 50001}`) that the
  /// address space will dispatch to the test namespace.
  uint16_t install_test_namespace(ua::AddressSpace& addressSpace, std::string_view uri)
  {
    auto testNs = ua::default_ns::Namespace::create(std::string{uri}, mServerThreadPool.executor());
    return addressSpace.add_namespace_sync(testNs);
  }

  /// Resolve a namespace index to its registered URI via the server's
  /// `NamespaceArray`. Part 18 section 4.2.2 declares AddRole's 2nd input argument
  /// as `NamespaceUri : String`, so RBAC tests pass the URI on the wire; this
  /// helper recovers the URI for a known index (e.g. index 1 = the server's
  /// own application-URI namespace, whose URI is non-deterministic per test
  /// run) without hard-coding it.
  ua::String namespace_uri_for_index(uint16_t index)
  {
    return mServer->address_space().namespace_array().get_namespace_uri(index);
  }

  /// Create an Int32 Variable in `addressSpace` with the given NodeId,
  /// `RolePermissions` list, AccessLevel = Read+Write, and an organize
  /// reference from `ObjectsFolder`. Returns the NodeId for convenience.
  static ua::NodeId create_role_gated_variable(ua::AddressSpace& addressSpace, const ua::NodeId& nodeId,
    const std::string& browseName, std::vector<ua::RolePermissionType> rolePermissions,
    int32_t initialValue = 0)
  {
    auto namespaceIndex = nodeId.namespace_index();
    auto varNode = addressSpace.create_node_sync(nodeId, ua::NodeClass::Variable);
    auto variable = varNode.as<ua::VariableAccessor>();
    if (!variable.has_value())
    {
      ADD_FAILURE() << "create_node_sync did not return a VariableAccessor for " << browseName;
      return nodeId;
    }
    variable->set_browse_name(ua::QualifiedName{namespaceIndex, browseName});
    variable->set_display_name(ua::LocalizedText{"", browseName});
    variable->set_data_type(ua::NodeId{ua::DataTypeId::Int32});
    variable->write_value_sync(initialValue);
    variable->set_access_level(
      ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::CurrentWrite});
    varNode.set_role_permissions(std::move(rolePermissions));

    auto objectsFolder = addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, nodeId);
    return nodeId;
  }

  /// Read the `Identities` Property of a well-known Role Object over the
  /// wire and decode it into the SDK structure-array representation.
  std::vector<ua::IdentityMappingRuleType> read_role_identities(
    ua::client::Session& session, ua::NodeId identitiesNodeId)
  {
    auto resp = session.attributes().read_sync(ua::test_helpers::read_value(identitiesNodeId));

    EXPECT_THAT(resp, ua::test_helpers::ServiceResultIsGood());
    if (resp.results().empty())
      return {};
    EXPECT_THAT(resp.results()[0], ua::test_helpers::Good());

    std::vector<ua::IdentityMappingRuleType> out;
    const auto& value = resp.results()[0].value();
    if (!value.is_array())
      return out;
    const auto& arr = value.as<ua::Array<ua::RefStructure<ua::Structure>>>();
    out.reserve(arr.size());
    for (size_t i = 0; i < arr.size(); ++i)
    {
      const auto* rule = dynamic_cast<const ua::IdentityMappingRuleType*>(arr.payload()[i].get());
      if (rule == nullptr)
      {
        ADD_FAILURE() << "Identities array element " << i << " is not an IdentityMappingRuleType";
        return out;
      }
      out.push_back(*rule);
    }
    return out;
  }

  std::shared_ptr<ua::server::RoleConfiguration> roleConfiguration;
};

#endif  // UA_TEST_ROLE_BASED_SECURITY_FIXTURE_H
