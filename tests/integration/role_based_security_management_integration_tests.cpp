// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// CTT-mirror integration tests for the Step 6 / Phase P2 method-handler
/// gating + AddRole hardening cluster (Part 18 Role-Based Security,
/// SVR-SECADMIN-035..045).
///
/// These stand up a full Part-18-wired server with role management enabled
/// (`ServerConfig::roleManagementEnabled = true`, set by the
/// `ComplianceRoleBasedSecurity` fixture) and a real Client, then exercise the
/// RoleSet management Methods over the wire. They prove, end-to-end, the P2
/// gates that the unit and service suites exercise:
///   * ordinary per-Node RolePermissions grant the SecurityAdmin Role and deny
///     non-administrative identities,
///   * SignAndEncrypt on the per-role surface (Part 18 section 4.4.1) and on RoleSet-level
///     AddRole and RemoveRole (Part 18 sections 4.2.2 and 4.2.3),
///   * AddRole hardening (BrowseName uniqueness, well-known NodeId reuse,
///     default `*Exclude = TRUE`).
///
/// Falsifiability: the management Methods are admin-gated at the per-Node authz
/// layer too, so a negative-only test would pass even against a deny-everyone
/// bug (the RoleSet AddRole/RemoveRole Methods had no RolePermissions before
/// this phase - fail-closed denies *all* callers). Each admin-gate mirror
/// therefore pins BOTH a non-admin denial (`Bad_UserAccessDenied`) AND an admin
/// success - the success is the real end-to-end proof that the caller's
/// resolved Role identity is presented to the target Namespace, whose ordinary
/// permission evaluation authorises the Call before handler dispatch.
///
/// The Method service enforces EncryptionRequired before handler dispatch. An administrator's
/// unencrypted AddRole or RemoveRole returns Bad_SecurityModeInsufficient, while an encrypted
/// non-administrator call is refused by the independent permission check.
///
/// Admin sessions authenticate as the UserName "admin", mapped to the
/// well-known SecurityAdmin Role by `grant_security_admin_to_user`. Non-admin
/// sessions are plain Anonymous (only the Anonymous Role). SecurityAdmin - the
/// GDS cert-push admin role - is never granted to an Anonymous session.
///
/// Coverage map (SECADMIN-035..045 - all P2-closed):
///   * AddRoleBrowseNameUniqueness          - SECADMIN-035
///   * AddRoleDefaultExcludes               - SECADMIN-036
///   * AddRole{AdminSucceeds,NonAdminDenied,SignChannelFloorRejected} - SECADMIN-037
///   * AddRoleWellKnownNodeIdReuse          - SECADMIN-038
///   * RemoveRole{AdminSucceeds,NonAdminDenied,SignChannelFloorRejected} - SECADMIN-039
///   * AddIdentity{AdminSucceeds,NonAdminDenied,SignChannelFloorRejected} - SECADMIN-040
///   * RemoveIdentity{AdminSucceeds,NonAdminDenied}        - SECADMIN-041
///   * AddApplication{AdminSucceeds,NonAdminDenied}        - SECADMIN-042
///   * RemoveApplication{AdminSucceeds,NonAdminDenied}     - SECADMIN-043
///   * AddEndpoint{AdminSucceeds,NonAdminDenied}           - SECADMIN-044
///   * RemoveEndpoint{AdminSucceeds,NonAdminDenied}        - SECADMIN-045

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "certificate_validation_request_helpers.h"
#include "helpers/role_based_security_fixture.h"
#include "helpers/rbac_server_certificate_validation_fixture.h"

#include "matchers.h"
#include "requests.h"

// The server-side certificate-validation obligations at the end of this file drive a real OPN
// handshake and a real SecurityToken renewal, so they need the client SecureChannel's renewal interface
// (the same one `client_cert_validation_matrix_tests.cpp` uses) rather than a wall-clock timer.
#include "ua_client_secure_channel_test_access.h"

#include "ua_array.h"
#include "ua_attribute_write_mask.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_create_monitored_items_request.h"
#include "ua_create_monitored_items_response.h"
#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_endpoint_description.h"
#include "ua_endpoint_type.h"
#include "ua_get_endpoints_request.h"
#include "ua_get_endpoints_response.h"
#include "ua_namespace_history_delegate.h"
#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_read_result.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_localized_text.h"
#include "ua_method_id.h"
#include "ua_namespace.h"
#include "ua_namespace_uri.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_reference_description.h"
#include "ua_role_permission_type.h"
#include "ua_session_method_services.h"
#include "ua_session_monitored_item_services.h"
#include "ua_session_subscription_services.h"
#include "ua_session_view_services.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_timestamps_to_return.h"
#include "ua_utc_time.h"
#include "ua_variable_id.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_well_known_role_permissions.h"
#include "ua_x509_certificate.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

constexpr uint32_t roleSetId = static_cast<uint32_t>(ObjectId::Server_ServerCapabilities_RoleSet);
constexpr uint32_t addRoleMethodId =
  static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_AddRole);
constexpr uint32_t removeRoleMethodId =
  static_cast<uint32_t>(MethodId::Server_ServerCapabilities_RoleSet_RemoveRole);

// Observer role Object - deleted by the well-known-reuse fixture so AddRole
// takes the spec-NodeId path instead of colliding (mirrors the unit test
// `AddRoleWithWellKnownNameUsesSpecNodeId`).
constexpr uint32_t observerRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Observer);

// Operator role Object + its per-role management Methods (kPerRoleMethods in
// ua_role_method_handlers.cpp). Operator is a convenient mutation target - it
// ships with no default identity rules / applications / endpoints.
constexpr uint32_t operatorRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_Operator);
constexpr uint32_t operatorAddIdentityMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_AddIdentity);
constexpr uint32_t operatorRemoveIdentityMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_RemoveIdentity);
constexpr uint32_t operatorAddApplicationMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_AddApplication);
constexpr uint32_t operatorRemoveApplicationMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_RemoveApplication);
constexpr uint32_t operatorAddEndpointMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_AddEndpoint);
constexpr uint32_t operatorRemoveEndpointMethod =
  static_cast<uint32_t>(MethodId::WellKnownRole_Operator_RemoveEndpoint);

IdentityMappingRuleType username_rule(std::string criteria)
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{std::move(criteria)};
  return rule;
}

EndpointType endpoint(std::string url)
{
  EndpointType ep;
  ep.endpoint_url() = String{std::move(url)};
  return ep;
}

void grant_engineer_to_user(RoleConfiguration& config, const std::string& userId)
{
  RoleConfiguration::RoleDefinition definition;
  definition.roleId = well_known_role_node_id(WellKnownRole::Engineer);
  definition.roleBit = well_known_role_bit(WellKnownRole::Engineer).value();
  ASSERT_TRUE(config.add_role(std::move(definition))) << "Engineer Role slot must register";
  auto result =
    config.add_identity_rule(well_known_role_node_id(WellKnownRole::Engineer), username_rule(userId));
  ASSERT_TRUE(result.is_good()) << result.status_code().value();
}

/// Call a Method over the wire and return the per-operation StatusCode (or the
/// service-level result if the request itself failed / returned no results).
StatusCode call_status(
  Session& session, const NodeId& objectId, const NodeId& methodId, std::initializer_list<Variant> args)
{
  auto resp = session.methods().call_sync(call_method(objectId, methodId, args));
  if (!resp.response_header().service_result().is_good())
  {
    return resp.response_header().service_result();
  }
  if (resp.results().empty())
  {
    return StatusCode{Status::BadInternalError};
  }
  return resp.results()[0].status_code();
}

/// Invoke AddRole and return the allocated Role NodeId from output argument 0.
/// Fails the test (via the matcher) and returns a null NodeId if the call did
/// not produce a Good per-operation result with a NodeId output.
///
/// `namespaceUri` is the spec-conformant 2nd input argument (Part 18 section 4.2.2:
/// AddRole(RoleName: String, NamespaceUri: String)). Callers pass the URI of
/// the namespace the new Role should belong to; the server resolves it to an
/// index internally.
NodeId add_role(Session& session, const std::string& roleName, const String& namespaceUri)
{
  auto resp = session.methods().call_sync(call_method(
    NodeId{0, roleSetId}, NodeId{0, addRoleMethodId}, {Variant{String{roleName}}, Variant{namespaceUri}}));
  EXPECT_THAT(resp, ServiceResultIsGood());
  if (resp.results().empty() || !resp.results()[0].status_code().is_good() ||
      resp.results()[0].output_arguments().empty())
  {
    return NodeId{};
  }
  const auto* id = resp.results()[0].output_arguments()[0].try_as<NodeId>();
  return id ? *id : NodeId{};
}

// Pre-existing per-role state seeded on Operator by `seed_operator_rules`. A
// refusal test that observes "nothing was added / nothing was removed" against
// an empty list proves nothing, so every such fixture starts with one rule and
// one application already in place.
constexpr const char* seededIdentity = "seeded-operator-user";
constexpr const char* seededApplicationUri = "urn:seeded:operator:app";

/// Seed one UserName identity rule and one permitted application on the
/// Operator Role in the server's live `RoleConfiguration`. Called from
/// `customize_address_space` (i.e. after `Server::create`, once
/// `seed_well_known_roles` has registered Operator).
void seed_operator_rules(RoleConfiguration& config)
{
  auto identity =
    config.add_identity_rule(NodeId{0, operatorRoleId}, username_rule(std::string{seededIdentity}));
  ASSERT_TRUE(identity.is_good()) << "seed identity rule must register: " << identity.status_code().value();
  ASSERT_TRUE(config.add_application(NodeId{0, operatorRoleId}, String{std::string{seededApplicationUri}}))
    << "seed application URI must register";
}

/// Number of UserName identity rules on `roleId` whose criteria equals
/// `criteria`, read back from the server's live `RoleConfiguration` - the state
/// AccessIdentity construction actually consults, not a test-local copy.
size_t count_username_rules(
  const RoleConfiguration& config, const NodeId& roleId, const std::string& criteria)
{
  auto def = config.get_role(roleId);
  if (!def)
  {
    return 0;
  }
  size_t count = 0;
  for (const auto& rule : def->identities)
  {
    if (rule.criteria_type() == IdentityCriteriaType::UserName && rule.criteria() == String{criteria})
    {
      ++count;
    }
  }
  return count;
}

/// Number of permitted-application entries on `roleId` equal to `uri`.
size_t count_applications(const RoleConfiguration& config, const NodeId& roleId, const std::string& uri)
{
  auto def = config.get_role(roleId);
  if (!def)
  {
    return 0;
  }
  size_t count = 0;
  for (const auto& application : def->applications)
  {
    if (application == String{uri})
    {
      ++count;
    }
  }
  return count;
}

/// True iff the browse of `objectId` returned a forward reference whose
/// BrowseName is `browseName`. Used to pin the "not browseable" half of the
/// Part 18 admin clauses - the Method must not be discoverable by a caller who
/// may not call it.
bool browse_exposes_child(Session& session, const NodeId& objectId, const std::string& browseName)
{
  auto resp = session.view().browse_sync(browse(objectId));
  EXPECT_THAT(resp, ServiceResultIsGood());
  if (resp.results().empty())
  {
    return false;
  }
  for (const auto& reference : resp.results()[0].references())
  {
    if (reference.browse_name().name() == String{browseName})
    {
      return true;
    }
  }
  return false;
}

}  // namespace

// ============================================================================
// Shared fixtures: an admin session vs a non-admin session.
// ============================================================================

/// SecurityAdmin session: authenticates as UserName "admin", which
/// `grant_security_admin_to_user` maps to the well-known SecurityAdmin Role.
/// Every session opened on this fixture is an administrator.
class RbacManagementAdminFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "admin");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "admin", std::unordered_map<std::string, std::string>{});
  }
};

/// Wave I strengthening (configuration coverage matrix section 12): `roleManagementEnabled` is a GATE, and
/// every fixture in this file leaves it at the `true` the RBAC fixture sets. The disabled path - the SDK
/// installs no Call handlers for the management Methods (`ServerImpl::wire_authorizer`) - was covered only
/// by `role_method_handlers_tests.cpp:448`, a unit test against the handler in isolation. Per section 1 rule
/// 5 an enable-flag needs its OFF case: an over-firing gate (management Methods reachable when the operator
/// disabled them) is as much a defect as an inert one, and no integration test would have caught it.
///
/// This fixture is RbacManagementAdminFixture with the gate turned off and nothing else changed - same
/// admin identity, same SecurityAdmin grant, same call. So the oracle is the gate alone: an admin who
/// succeeds under the ON fixture must be refused here, and NOT because of authorization.
class RbacManagementDisabledFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "admin");
  }

  // Runs AFTER the base sets roleManagementEnabled = true, so this is the override that disables it.
  void customize_server_configuration(ua::server::ServerConfig& serverConfig) override
  {
    serverConfig.roleManagementEnabled = false;  // the RBAC fixture default is true
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "admin", std::unordered_map<std::string, std::string>{});
  }
};

/// Row: ServerConfig::roleManagementEnabled - the OFF case.
TEST_F(RbacManagementDisabledFixture, AddRoleUnavailableWhenRoleManagementDisabled)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleDisabled");
  const auto status = call_status(session,
    NodeId{0, roleSetId},
    NodeId{0, addRoleMethodId},
    {Variant{String{"ShouldNotBeCreated"}}, Variant{namespace_uri_for_index(1)}});

  EXPECT_NE(status, Status::Good)
    << "with roleManagementEnabled=false the management Method must not be callable; the identical call "
       "by this same admin returns Good under RbacManagementAdminFixture, so only the gate differs";
  EXPECT_NE(status, Status::BadUserAccessDenied)
    << "the refusal must come from the ABSENT handler, not from authorization - this session holds "
       "SecurityAdmin, and a denial on access grounds would mean the gate is not what refused it";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

/// Non-admin session: default Anonymous authenticator, no admin grant. The
/// connecting session resolves to the Anonymous Role only.
class RbacManagementNonAdminFixture : public ComplianceRoleBasedSecurity
{};

// ============================================================================
// SECADMIN-035 - AddRole BrowseName uniqueness within the RoleSet Object
// (Part 18 section 4.2.2 lines 314, 346)
// ============================================================================

// @relation(SVR-SECADMIN-035, scope=function)
TEST_F(RbacManagementAdminFixture, AddRoleBrowseNameUniqueness)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleUnique");

  const String customNamespaceUri = namespace_uri_for_index(1);
  // First AddRole creates a RoleSet child named "DuplicateRole".
  EXPECT_EQ(call_status(session,
              NodeId{0, roleSetId},
              NodeId{0, addRoleMethodId},
              {Variant{String{"DuplicateRole"}}, Variant{customNamespaceUri}}),
    Status::Good);
  // Second AddRole with the same BrowseName collides -> Bad_InvalidArgument.
  EXPECT_EQ(call_status(session,
              NodeId{0, roleSetId},
              NodeId{0, addRoleMethodId},
              {Variant{String{"DuplicateRole"}}, Variant{customNamespaceUri}}),
    Status::BadInvalidArgument);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-036 - AddRole-created Role defaults *Exclude = TRUE
// (Part 18 section 4.2.2 lines 316-318)
// ============================================================================

// Discharges AC-SVR-SECADMIN-036-ADDROLE-EXCLUDE-PROPERTIES, which names this test in its
// retired test backlog. The criterion's "where the server supports them they are present and
// writable" is the spec's own conditional: Part 18 section 4.2.2 L316-318 obliges the initial
// VALUES only "if the optional Properties ... are available on the Role Object created with
// this Method", both are declared on NS0 `RoleType` with the Optional modelling rule (i=80),
// and SVR-SECADMIN-036's APPLICABILITY repeats the condition ("... AND the Role Object carries
// the optional Exclude Properties"). Presence on an AddRole-created Role is therefore the
// requirement's antecedent, not its obligation. This server's AddRole does instantiate both
// Properties (and the six RoleType management Methods, AC-SVR-ROLE-ADDROLE-ROLES-CARRY-MANAGEMENT-METHODS),
// but the defaults are observed here on the RoleConfiguration the Role evaluator consults, which is
// what decides access.
// @relation(SVR-SECADMIN-036, scope=function)
// @verifies AC-SVR-SECADMIN-036-ADDROLE-EXCLUDE-PROPERTIES
TEST_F(RbacManagementAdminFixture, AddRoleDefaultExcludes)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleExcludes");

  const NodeId newRoleId = add_role(session, "ExcludeDefaultRole", namespace_uri_for_index(1));
  ASSERT_FALSE(newRoleId.is_null());

  // The defaults are observed on the server's RoleConfiguration state, which decides access - the
  // wire call drove the handler, which set both to TRUE.
  auto def = roleConfiguration->get_role(newRoleId);
  ASSERT_TRUE(def);
  EXPECT_TRUE(def->applicationsExclude)
    << "AddRole must default ApplicationsExclude to TRUE (Part 18 section 4.2.2 L316-318)";
  EXPECT_TRUE(def->endpointsExclude)
    << "AddRole must default EndpointsExclude to TRUE (Part 18 section 4.2.2 L316-318)";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-037 - AddRole requires administrator credentials and an encrypted channel
// (Part 18 section 4.2.2)
// ============================================================================

// @relation(SVR-SECADMIN-037, scope=function)
TEST_F(RbacManagementAdminFixture, AddRoleAdminSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, roleSetId},
              NodeId{0, addRoleMethodId},
              {Variant{String{"AdminCreatedRole"}}, Variant{namespace_uri_for_index(1)}}),
    Status::Good);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementNonAdminFixture, AddRoleNonAdminDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleNonAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, roleSetId},
              NodeId{0, addRoleMethodId},
              {Variant{String{"ForbiddenRole"}}, Variant{namespace_uri_for_index(1)}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-SECADMIN-037-ENCRYPTED-CHANNEL, scope=function)
TEST_F(RbacManagementAdminFixture, AddRoleSignChannelFloorRejected)
{
  auto [channel, session] = open_session(MessageSecurityMode::Sign, "AddRoleSign");
  const std::initializer_list<Variant> arguments{
    Variant{String{"SignChannelRole"}}, Variant{namespace_uri_for_index(1)}};
  EXPECT_EQ(call_status(session, NodeId{0, roleSetId}, NodeId{0, addRoleMethodId}, arguments),
    Status::BadSecurityModeInsufficient);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();

  // The identical encrypted retry also proves that the rejected call did not create the Role.
  auto [encryptedChannel, encryptedSession] =
    open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleEncryptedRetry");
  EXPECT_EQ(
    call_status(encryptedSession, NodeId{0, roleSetId}, NodeId{0, addRoleMethodId}, arguments), Status::Good);
  (void)encryptedSession.try_close_sync();
  (void)encryptedChannel.try_close_sync();
}

// ============================================================================
// SECADMIN-038 - AddRole for a well-known Role name under ns0 reuses the spec NodeId
// (Part 18 section 4.2.2 lines 322-325)
// ============================================================================

/// Removes the materialised Observer Role (Object + registration) before the
/// test so AddRole("Observer", ns0) takes the well-known-NodeId-reuse path
/// rather than colliding with the existing RoleSet child.
class AddRoleWellKnownReuseFixture : public RbacManagementAdminFixture
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    (void)addressSpace.try_delete_node_sync(
      NodeId{0, observerRoleId}, /*deleteForwardHierarchicalRefs=*/true);
    roleConfiguration->remove_role(NodeId{0, observerRoleId});
  }
};

// @relation(SVR-SECADMIN-038, scope=function)
TEST_F(AddRoleWellKnownReuseFixture, AddRoleWellKnownNodeIdReuse)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleWellKnown");

  const NodeId newRoleId = add_role(session, "Observer", String{specNamespaceUri});
  EXPECT_EQ(newRoleId, (NodeId{0, observerRoleId}))
    << "Well-known Role name under ns0 must reuse the spec NodeId (Part 18 section 4.2.2 L322-325)";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-039 - RemoveRole requires administrator credentials and an encrypted channel
// (Part 18 section 4.2.3)
// ============================================================================

// @relation(SVR-SECADMIN-039, scope=function)
TEST_F(RbacManagementAdminFixture, RemoveRoleAdminSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveRoleAdmin");

  const NodeId roleId = add_role(session, "RoleToRemove", namespace_uri_for_index(1));
  ASSERT_FALSE(roleId.is_null());
  EXPECT_EQ(call_status(session, NodeId{0, roleSetId}, NodeId{0, removeRoleMethodId}, {Variant{roleId}}),
    Status::Good);
  EXPECT_FALSE(roleConfiguration->get_role(roleId))
    << "RemoveRole must drop the role from the RoleConfiguration";

  // The role Object must already be gone from the address space the instant
  // RemoveRole reports Good: the handler sequences its completion after the
  // asynchronous node delete, so a client never observes Good while the node is
  // still browsable. Read an attribute over the wire to confirm deterministically.
  auto readBack = session.attributes().read_sync(read_value(roleId, AttributeId::NodeClass));
  ASSERT_THAT(readBack, ServiceResultIsGood());
  ASSERT_FALSE(readBack.results().empty());
  EXPECT_THAT(readBack.results()[0], HasStatus(Status::BadNodeIdUnknown))
    << "RemoveRole reported Good but the role Object is still readable";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementNonAdminFixture, RemoveRoleNonAdminDenied)
{
  // Non-admin cannot remove an existing well-known Role (Operator). The admin
  // gate denies before any existence check.
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveRoleNonAdmin");
  EXPECT_EQ(
    call_status(
      session, NodeId{0, roleSetId}, NodeId{0, removeRoleMethodId}, {Variant{NodeId{0, operatorRoleId}}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-SECADMIN-039-ENCRYPTED-CHANNEL, scope=function)
TEST_F(RbacManagementAdminFixture, RemoveRoleSignChannelFloorRejected)
{
  auto [channel, session] = open_session(MessageSecurityMode::Sign, "RemoveRoleSign");
  const std::initializer_list<Variant> arguments{Variant{NodeId{0, operatorRoleId}}};
  EXPECT_EQ(call_status(session, NodeId{0, roleSetId}, NodeId{0, removeRoleMethodId}, arguments),
    Status::BadSecurityModeInsufficient);
  EXPECT_TRUE(roleConfiguration->get_role(NodeId{0, operatorRoleId}));
  (void)session.try_close_sync();
  (void)channel.try_close_sync();

  // The identical encrypted retry proves that the denied call left the Role available to remove.
  auto [encryptedChannel, encryptedSession] =
    open_session(MessageSecurityMode::SignAndEncrypt, "RemoveRoleEncryptedRetry");
  EXPECT_EQ(call_status(encryptedSession, NodeId{0, roleSetId}, NodeId{0, removeRoleMethodId}, arguments),
    Status::Good);
  EXPECT_FALSE(roleConfiguration->get_role(NodeId{0, operatorRoleId}));
  (void)encryptedSession.try_close_sync();
  (void)encryptedChannel.try_close_sync();
}

// ============================================================================
// SECADMIN-040 - AddIdentity requires an encrypted channel AND admin rights
// (Part 18 section 4.4.5 lines 870-874)
// ============================================================================

// @relation(SVR-SECADMIN-040, scope=function)
TEST_F(RbacManagementAdminFixture, AddIdentityAdminSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddIdentityAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("alice")}}),
    Status::Good);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementNonAdminFixture, AddIdentityNonAdminDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddIdentityNonAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("alice")}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementAdminFixture, AddIdentitySignChannelFloorRejected)
{
  // Encrypted-channel mandate (Part 18 section 4.4.5): an admin caller on a Sign-only
  // channel is rejected with Bad_SecurityModeInsufficient.
  auto [channel, session] = open_session(MessageSecurityMode::Sign, "AddIdentitySign");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("alice")}}),
    Status::BadSecurityModeInsufficient);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-041 - RemoveIdentity requires admin rights (Part 18 section 4.4.6 L898-899)
// ============================================================================

// @relation(SVR-SECADMIN-041, scope=function)
TEST_F(RbacManagementAdminFixture, RemoveIdentityAdminSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveIdentityAdmin");

  // Seed an identity rule, then remove it.
  ASSERT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("bob")}}),
    Status::Good);
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveIdentityMethod},
              {Variant{username_rule("bob")}}),
    Status::Good);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementNonAdminFixture, RemoveIdentityNonAdminDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveIdentityNonAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveIdentityMethod},
              {Variant{username_rule("bob")}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-042 - AddApplication requires admin rights (Part 18 section 4.4.7 L922-923)
// ============================================================================

// @relation(SVR-SECADMIN-042, scope=function)
TEST_F(RbacManagementAdminFixture, AddApplicationAdminSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddApplicationAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddApplicationMethod},
              {Variant{String{"urn:trusted:client"}}}),
    Status::Good);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementNonAdminFixture, AddApplicationNonAdminDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddApplicationNonAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddApplicationMethod},
              {Variant{String{"urn:trusted:client"}}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-043 - RemoveApplication requires admin rights (Part 18 section 4.4.8 L947-948)
// ============================================================================

// @relation(SVR-SECADMIN-043, scope=function)
TEST_F(RbacManagementAdminFixture, RemoveApplicationAdminSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveApplicationAdmin");

  ASSERT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddApplicationMethod},
              {Variant{String{"urn:trusted:client"}}}),
    Status::Good);
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveApplicationMethod},
              {Variant{String{"urn:trusted:client"}}}),
    Status::Good);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementNonAdminFixture, RemoveApplicationNonAdminDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveApplicationNonAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveApplicationMethod},
              {Variant{String{"urn:trusted:client"}}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-044 - AddEndpoint requires admin rights (Part 18 section 4.4.9 L970-971)
// ============================================================================

// @relation(SVR-SECADMIN-044, scope=function)
TEST_F(RbacManagementAdminFixture, AddEndpointAdminSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddEndpointAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddEndpointMethod},
              {Variant{endpoint("opc.tcp://server/secured")}}),
    Status::Good);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementNonAdminFixture, AddEndpointNonAdminDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddEndpointNonAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddEndpointMethod},
              {Variant{endpoint("opc.tcp://server/secured")}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-045 - RemoveEndpoint requires admin rights (Part 18 section 4.4.10 L997-998)
// ============================================================================

// @relation(SVR-SECADMIN-045, scope=function)
TEST_F(RbacManagementAdminFixture, RemoveEndpointAdminSucceeds)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveEndpointAdmin");

  ASSERT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddEndpointMethod},
              {Variant{endpoint("opc.tcp://server/secured")}}),
    Status::Good);
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveEndpointMethod},
              {Variant{endpoint("opc.tcp://server/secured")}}),
    Status::Good);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(RbacManagementNonAdminFixture, RemoveEndpointNonAdminDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveEndpointNonAdmin");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveEndpointMethod},
              {Variant{endpoint("opc.tcp://server/secured")}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// The configurability control that replaces the former handler-level administrator list. Both servers
// register the same Engineer Role and map the same authenticated user to it. Only the first authors
// ordinary RolePermissions on the Role-management surface. There is no handler-level Role predicate.
class RbacRoleManagementAuthoringFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_engineer_to_user(config, "engineer");
    const auto authored =
      config.grant_role_management_access({well_known_role_node_id(WellKnownRole::Engineer)});
    ASSERT_TRUE(authored.is_good()) << authored.status_code().value();
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "engineer", std::unordered_map<std::string, std::string>{});
  }
};

class RbacRoleManagementAuthoringControlFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_engineer_to_user(config, "engineer");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "engineer", std::unordered_map<std::string, std::string>{});
  }
};

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-NORMAL-POLICY, scope=function)
TEST_F(RbacRoleManagementAuthoringFixture, ConfiguredEngineerUsesOrdinaryRolePermissions)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ConfiguredEngineer");
  const auto engineerRole = well_known_role_node_id(WellKnownRole::Engineer);
  for (const auto nodeId : {NodeId{0, roleSetId}, NodeId{0, addRoleMethodId}})
  {
    auto readResponse = session.attributes().read_sync(
      ReadRequestBuilder{}.read(nodeId).attribute(AttributeId::RolePermissions).build());
    ASSERT_THAT(readResponse, ServiceResultIsGood());
    ASSERT_EQ(readResponse.results().size(), 1u);
    ASSERT_THAT(readResponse.results()[0], Good());
    const auto& encoded = readResponse.results()[0].value().as<Array<RefStructure<Structure>>>();
    const auto authored = std::find_if(encoded.begin(),
      encoded.end(),
      [&engineerRole](const RefStructure<Structure>& element)
      {
        const auto* entry = dynamic_cast<const RolePermissionType*>(element.get());
        return entry && entry->role_id() == engineerRole &&
               entry->permissions().test(PermissionType::Bit::Call);
      });
    EXPECT_NE(authored, encoded.end())
      << "the public helper must materialize inspectable ordinary policy on both Call subjects";
  }

  const auto status = call_status(session,
    NodeId{0, roleSetId},
    NodeId{0, addRoleMethodId},
    {Variant{String{"EngineerCreatedRole"}}, Variant{namespace_uri_for_index(1)}});
  EXPECT_EQ(status, Status::Good);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-COMP-SVR-ROLE-POLICY-AUTHORING-01-NORMAL-POLICY, scope=function)
TEST_F(RbacRoleManagementAuthoringControlFixture, UnconfiguredEngineerRemainsDenied)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "UnconfiguredEngineer");
  const auto status = call_status(session,
    NodeId{0, roleSetId},
    NodeId{0, addRoleMethodId},
    {Variant{String{"EngineerMustNotCreateThis"}}, Variant{namespace_uri_for_index(1)}});
  EXPECT_EQ(status, Status::BadUserAccessDenied);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// Round-2 obligations: the halves of SECADMIN-036..042 that the mirrors above
// leave unobserved - the Exclude Properties as a client sees them, the
// browse-visibility half of the admin clauses, and the "and nothing changed"
// half of every refusal.
// ============================================================================

/// Operator seeded with one identity rule and one permitted application, on a
/// non-administrator (Anonymous) session. The seeding is what makes the
/// "unchanged" assertions falsifiable: an empty list cannot distinguish "the
/// refusal held the state" from "there was never any state".
class RbacSeededOperatorNonAdminFixture : public ComplianceRoleBasedSecurity
{
protected:
  // Runs after `Server::create`, so `seed_well_known_roles` has already
  // registered Operator and the per-role mutators find it.
  void customize_address_space(AddressSpace& /*addressSpace*/) override
  {
    seed_operator_rules(*roleConfiguration);
  }
};

/// Same seeding, administrator identity - for the guard whose antecedent is
/// "holds administrator rights but is on an unencrypted channel".
class RbacSeededOperatorAdminFixture : public RbacManagementAdminFixture
{
protected:
  void customize_address_space(AddressSpace& /*addressSpace*/) override
  {
    seed_operator_rules(*roleConfiguration);
  }
};

// AC-SVR-SECADMIN-036-ADDROLE-EXCLUDE-PROPERTIES is discharged by
// `AddRoleDefaultExcludes` above; see the note there for why no client-side
// presence/writability mirror belongs in this file.

// Part 18 section 4.2.2 L320-321: AddRole "shall only be browseable and callable by
// authorized administrators". The half-implementation is the common one - refuse the
// Call, leave the Method in the browse tree - and it leaks to an unauthorised caller
// both that the capability exists and exactly where to aim once it acquires
// credentials. Both conjuncts are asserted here.
// @verifies AC-SVR-SECADMIN-037-ADDROLE-ADMIN
TEST_F(RbacManagementNonAdminFixture, AddRoleIsNeitherBrowseableNorCallableWithoutAdminRights)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleBrowseHidden");

  // Non-vacuity: the Method node really is on this server (server-side view, no
  // authorization applied), so an absent reference below is the authorization filter
  // at work and not a Method that was never wired.
  auto addressSpace = mServer->address_space();
  ASSERT_TRUE(addressSpace.try_find_node_sync(NodeId{0, addRoleMethodId}))
    << "the AddRole Method must exist on the server for its absence from the browse to mean anything";

  EXPECT_FALSE(browse_exposes_child(session, NodeId{0, roleSetId}, "AddRole"))
    << "AddRole must not appear when a non-administrator browses the RoleSet Object (Part 18 section 4.2.2 "
       "L320-321) - refusing the Call while advertising the Method satisfies only half the clause";

  EXPECT_EQ(call_status(session,
              NodeId{0, roleSetId},
              NodeId{0, addRoleMethodId},
              {Variant{String{"ForbiddenBrowseRole"}}, Variant{namespace_uri_for_index(1)}}),
    Status::BadUserAccessDenied)
    << "and the Call itself must be refused";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.2.3 L364-365: RemoveRole "shall only be browseable and callable by
// authorized administrators". Same failure mode as its creation-side twin, and worse
// consequence: the Method a non-administrator can see is the one that dismantles the
// role configuration. Hiding without refusing, or refusing without hiding, satisfies
// neither half.
// @verifies AC-SVR-SECADMIN-039-REMOVEROLE-ADMIN
TEST_F(RbacManagementNonAdminFixture, RemoveRoleIsNeitherBrowseableNorCallableWithoutAdminRights)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveRoleBrowseHidden");

  auto addressSpace = mServer->address_space();
  ASSERT_TRUE(addressSpace.try_find_node_sync(NodeId{0, removeRoleMethodId}))
    << "the RemoveRole Method must exist on the server for its absence from the browse to mean anything";

  EXPECT_FALSE(browse_exposes_child(session, NodeId{0, roleSetId}, "RemoveRole"))
    << "RemoveRole must not appear when a non-administrator browses the RoleSet Object (Part 18 section "
       "4.2.3 L364-365)";

  EXPECT_EQ(
    call_status(
      session, NodeId{0, roleSetId}, NodeId{0, removeRoleMethodId}, {Variant{NodeId{0, operatorRoleId}}}),
    Status::BadUserAccessDenied)
    << "and the Call itself must be refused";

  // The Role the refused call named must still be there: a refusal that removed the
  // Role anyway would report Bad and still be the denial of service the clause exists
  // to prevent.
  EXPECT_TRUE(roleConfiguration->get_role(NodeId{0, operatorRoleId}))
    << "the refused RemoveRole must not have removed the Operator Role";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.4.5 L870-874: the Client "shall use an encrypted channel AND shall
// provide user credentials with administrator rights". This is the half a server that
// checks only rights passes: the caller here holds SecurityAdmin, so the rights gate
// is satisfied and only the channel gate can refuse. The refusal must also leave the
// mapping alone - a server that mutates first and reports the violation afterwards
// has already granted the role.
// @verifies AC-SVR-SECADMIN-040-ADDIDENTITY-GUARDS
TEST_F(RbacSeededOperatorAdminFixture, AddIdentityRefusedOnUnencryptedChannelDespiteAdminRights)
{
  auto [channel, session] = open_session(MessageSecurityMode::Sign, "AddIdentityAdminUnencrypted");

  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("alice")}}),
    Status::BadSecurityModeInsufficient)
    << "administrator rights do not excuse the encrypted-channel guard (Part 18 section 4.4.5)";

  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, "alice"), 0u)
    << "the refused AddIdentity must not have added the rule";
  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, seededIdentity), 1u)
    << "and must have left the pre-existing rule untouched";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.4.5 L870-874, the other two combinations of the conjunction: no
// administrator rights over an encrypted channel (the half a server checking only the
// channel passes), and no rights over an unencrypted channel (the case a server with
// either single gate still refuses, so it proves nothing on its own and is included
// only to close the enumeration). Satisfying one guard does not excuse the other.
// @verifies AC-SVR-SECADMIN-040-ADDIDENTITY-GUARDS
TEST_F(RbacSeededOperatorNonAdminFixture, AddIdentityRefusedWithoutAdminRightsOnEitherChannel)
{
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddIdentityEncNoRights");
    EXPECT_EQ(call_status(session,
                NodeId{0, operatorRoleId},
                NodeId{0, operatorAddIdentityMethod},
                {Variant{username_rule("alice")}}),
      Status::BadUserAccessDenied)
      << "an encrypted channel does not excuse the administrator-rights guard (Part 18 section 4.4.5)";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  {
    auto [channel, session] = open_session(MessageSecurityMode::Sign, "AddIdentityUnencryptedNoRights");
    const auto status = call_status(session,
      NodeId{0, operatorRoleId},
      NodeId{0, operatorAddIdentityMethod},
      {Variant{username_rule("mallory")}});
    // Violating both guards at once must still be refused; which of the two the server
    // reports first is its own business, so both refusal codes are accepted here -
    // Good is not.
    EXPECT_TRUE(status == Status::BadUserAccessDenied || status == Status::BadSecurityModeInsufficient)
      << "a caller violating both guards must be refused, got " << status.value();
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, "alice"), 0u)
    << "no refused AddIdentity may add its rule";
  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, "mallory"), 0u)
    << "no refused AddIdentity may add its rule";
  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, seededIdentity), 1u)
    << "and the pre-existing rule must be untouched";
}

// Part 18 section 4.4.6 L898-899. Removal is as dangerous as addition and less obviously
// so: stripping the identities from a Role can lock every administrator out of the role
// configuration, a denial of service that cannot be undone through this interface. So
// the refusal alone is not the obligation - the mapping must still be there afterwards,
// which is what a server that mutates before it authorises would fail.
// @verifies AC-SVR-SECADMIN-041-REMOVEIDENTITY-ADMIN
TEST_F(RbacSeededOperatorNonAdminFixture, RemoveIdentityRefusedWithoutAdminRightsAndMappingUnchanged)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveIdentityUnchanged");

  // The rule named here exists - seeded on Operator - so the call is refused on
  // authorisation grounds and not because there was nothing to remove.
  ASSERT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, seededIdentity), 1u)
    << "fixture must seed the identity rule this test tries to remove";

  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveIdentityMethod},
              {Variant{username_rule(std::string{seededIdentity})}}),
    Status::BadUserAccessDenied);

  auto def = roleConfiguration->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_FALSE(def->identities.empty()) << "the refused RemoveIdentity emptied the Role's identity mapping";
  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, seededIdentity), 1u)
    << "the identity mapping must be unchanged after a refused RemoveIdentity";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.4.7 L922-923. Adding an application to a Role grants that Role to any
// client identified only by its ApplicationUri, so an unprivileged caller able to do it
// enrols itself. The refusal is only half the obligation: a server that appends the URI
// and then reports Bad has already handed over the Role, and the status code hides it.
// @verifies AC-SVR-SECADMIN-042-ADDAPPLICATION-ADMIN
TEST_F(RbacSeededOperatorNonAdminFixture, AddApplicationRefusedWithoutAdminRightsAndNothingAdded)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddApplicationUnchanged");

  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddApplicationMethod},
              {Variant{String{"urn:attacker:client"}}}),
    Status::BadUserAccessDenied);

  auto def = roleConfiguration->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_FALSE(def->applications.empty())
    << "the refused AddApplication must not have disturbed the seeded application list";
  EXPECT_EQ(count_applications(*roleConfiguration, NodeId{0, operatorRoleId}, "urn:attacker:client"), 0u)
    << "a refused AddApplication must not add the application to the Role";
  EXPECT_EQ(count_applications(*roleConfiguration, NodeId{0, operatorRoleId}, seededApplicationUri), 1u)
    << "and must leave the pre-existing entry in place";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// Round-3 obligations: the "and the list is unchanged" conjunct of the removal
// Methods, the endpoint-filter surface (which had no state-preservation mirror
// at all), and the client-visible arm of the AddRole exclude defaults - the one
// that engages where the created Role Object carries the Optional Properties.
// ============================================================================

namespace
{

// Pre-existing endpoint-filter entry seeded on Operator. The endpoint Methods had no
// seeded state before this: an "endpoint list unchanged" assertion against an empty
// list distinguishes nothing.
constexpr const char* seededEndpointUrl = "opc.tcp://seeded.operator.endpoint:4840";
constexpr const char* intrudedEndpointUrl = "opc.tcp://intruder.endpoint:4840";

/// Seed one endpoint-filter entry on the Operator Role in the server's live
/// `RoleConfiguration`. Called from `customize_address_space`, i.e. after
/// `Server::create` has run `seed_well_known_roles`.
void seed_operator_endpoint(RoleConfiguration& config)
{
  ASSERT_TRUE(config.add_endpoint(NodeId{0, operatorRoleId}, endpoint(std::string{seededEndpointUrl})))
    << "seed endpoint filter entry must register";
}

/// Number of endpoint-filter entries on `roleId` whose EndpointUrl equals `url`,
/// read back from the server's live `RoleConfiguration`.
size_t count_endpoints(const RoleConfiguration& config, const NodeId& roleId, const std::string& url)
{
  auto def = config.get_role(roleId);
  if (!def)
  {
    return 0;
  }
  size_t count = 0;
  for (const auto& entry : def->endpoints)
  {
    if (entry.endpoint_url() == String{url})
    {
      ++count;
    }
  }
  return count;
}

/// NodeId of the forward-referenced child of `objectId` whose BrowseName is
/// `browseName`, or a null NodeId if the browse exposes no such child. The
/// NodeId-returning sibling of `browse_exposes_child`, for tests that must then
/// read or write the child.
NodeId find_child_node_id(Session& session, const NodeId& objectId, const std::string& browseName)
{
  auto resp = session.view().browse_sync(browse(objectId));
  EXPECT_THAT(resp, ServiceResultIsGood());
  if (resp.results().empty())
  {
    return NodeId{};
  }
  for (const auto& reference : resp.results()[0].references())
  {
    if (reference.browse_name().name() == String{browseName})
    {
      return reference.node_id().node_id();
    }
  }
  return NodeId{};
}

}  // namespace

/// Operator seeded with one endpoint-filter entry, on a non-administrator (Anonymous)
/// session - the endpoint counterpart of `RbacSeededOperatorNonAdminFixture`.
class RbacSeededEndpointNonAdminFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_address_space(AddressSpace& /*addressSpace*/) override
  {
    seed_operator_endpoint(*roleConfiguration);
  }
};

// Part 18 section 4.2.2 L316-318, read with section 4.5. The obligation is conditional and the
// condition is presence ON THE OBJECT THIS METHOD CREATED: "If the optional Properties
// EndpointsExclude and ApplicationsExclude are available on the Role Object created with this
// Method, the initial values ... shall be TRUE". SVR-SECADMIN-036 restates it in APPLICABILITY
// ("... AND the Role Object carries the optional Exclude Properties"), and both Properties carry
// the Optional modelling rule (i=80) on NS0 RoleType. Presence is therefore the antecedent, not
// the duty: failing because AddRole created the Role bare would assert the applicability
// condition as though it were the obligation, and would need a requirement obliging AddRole to
// instantiate RoleType's Optional members before it could mean anything.
//
// So the duty is asserted in two parts. Unconditionally, the wire Call must leave the new Role
// carrying the blacklist defaults in the state the filter predicates consult. Then, where the
// created Object does carry the Properties, this adds the address-space arm that
// `AddRoleDefaultExcludes` does not reach: initial value TRUE, and writable - the section 4.5
// carve-out that AC-SVR-SECADMIN-026-ROLE-PROPERTIES-NOT-WRITABLE names as its exception -
// where "writable" means the Write is accepted AND takes effect, not accepted and discarded.
// @verifies AC-SVR-SECADMIN-036-ADDROLE-EXCLUDE-PROPERTIES
TEST_F(RbacManagementAdminFixture, RoleCreatedByAddRoleHasExcludeDefaultsTrueAndWritableWherePresent)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleExcludeProps");

  const NodeId newRoleId = add_role(session, "ExcludePropertyRole", namespace_uri_for_index(1));
  ASSERT_FALSE(newRoleId.is_null());

  // The unconditional half: the Call drove the real AddRole handler, and the Role it registered
  // carries both defaults TRUE. This is the "blacklist + empty list" pairing SVR-SECADMIN-036's
  // STATEMENT turns on - with Exclude FALSE a freshly added Role would match no Application and
  // no Endpoint, i.e. be unreachable.
  auto def = roleConfiguration->get_role(newRoleId);
  ASSERT_TRUE(def) << "AddRole must register the new Role in the live RoleConfiguration";
  EXPECT_TRUE(def->applicationsExclude)
    << "AddRole must default ApplicationsExclude to TRUE (Part 18 section 4.2.2 L316-318)";
  EXPECT_TRUE(def->endpointsExclude)
    << "AddRole must default EndpointsExclude to TRUE (Part 18 section 4.2.2 L316-318)";

  for (const char* propertyName : {"ApplicationsExclude", "EndpointsExclude"})
  {
    const NodeId propertyId = find_child_node_id(session, newRoleId, propertyName);
    if (propertyId.is_null())
    {
      // Antecedent not met for this Role: the Optional Property was not materialised on the
      // Object AddRole created, so section 4.2.2's "if ... available on the Role Object created
      // with this Method" does not engage. The defaults asserted above are the whole of the
      // obligation here; the arms below arm themselves the day AddRole instantiates it.
      continue;
    }

    auto readResp = session.attributes().read_sync(read_value(propertyId));
    ASSERT_THAT(readResp, ServiceResultIsGood());
    ASSERT_FALSE(readResp.results().empty());
    EXPECT_THAT(readResp.results()[0], HasStatus(Status::Good)) << "read of " << propertyName;
    const auto* initial = readResp.results()[0].value().try_as<bool>();
    ASSERT_NE(initial, nullptr) << propertyName << " must be a Boolean";
    EXPECT_TRUE(*initial) << "the initial value of " << propertyName
                          << " on an AddRole-created Role shall be TRUE (Part 18 section 4.2.2 L316-318)";

    // Writable, the exception AC-SVR-SECADMIN-026-ROLE-PROPERTIES-NOT-WRITABLE names: the
    // Attribute advertises CurrentWrite, ...
    auto accessResp = session.attributes().read_sync(read_value(propertyId, AttributeId::AccessLevel));
    ASSERT_THAT(accessResp, ServiceResultIsGood());
    ASSERT_FALSE(accessResp.results().empty());
    const auto* accessLevel = accessResp.results()[0].value().try_as<uint8_t>();
    ASSERT_NE(accessLevel, nullptr) << "AccessLevel of " << propertyName << " is not a Byte";
    EXPECT_TRUE(AccessLevelType{*accessLevel}.test(AccessLevelType::Bit::CurrentWrite))
      << propertyName << " must advertise CurrentWrite";

    // ... the Write is accepted, and it takes effect. A Write that reports Good and leaves the
    // Attribute at its previous value is not a writable Property, it is a discarded one.
    auto writeResp =
      session.attributes().write_sync(WriteRequestBuilder{}.write(propertyId, Variant{false}).build());
    ASSERT_THAT(writeResp, ServiceResultIsGood());
    ASSERT_FALSE(writeResp.results().empty());
    EXPECT_EQ(writeResp.results()[0].as_status(), Status::Good)
      << propertyName << " must accept a direct Write (Part 18 section 4.5 carve-out)";

    auto readBack = session.attributes().read_sync(read_value(propertyId));
    ASSERT_THAT(readBack, ServiceResultIsGood());
    ASSERT_FALSE(readBack.results().empty());
    const auto* written = readBack.results()[0].value().try_as<bool>();
    ASSERT_NE(written, nullptr) << propertyName << " read-back is not a Boolean";
    EXPECT_FALSE(*written) << "the accepted Write of " << propertyName << " must take effect";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.4.8 L947-948. Removal is the direction that silently widens: dropping the
// application a Role was restricted to can hand that Role to clients the administrator had
// excluded, and unlike an addition it leaves nothing behind to notice. So refusing the Call is
// only half the obligation - a server that mutates the list and then reports Bad has already
// done the damage, and the status code conceals it. The URI named here is really assigned to
// the Role, so the refusal is on authorisation grounds and not because there was nothing to
// remove.
// @verifies AC-SVR-SECADMIN-043-REMOVEAPPLICATION-ADMIN
TEST_F(RbacSeededOperatorNonAdminFixture, RemoveApplicationRefusedWithoutAdminRightsAndListUnchanged)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveApplicationUnchanged");

  ASSERT_EQ(count_applications(*roleConfiguration, NodeId{0, operatorRoleId}, seededApplicationUri), 1u)
    << "fixture must seed the application this test tries to remove";

  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveApplicationMethod},
              {Variant{String{std::string{seededApplicationUri}}}}),
    Status::BadUserAccessDenied);

  auto def = roleConfiguration->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_FALSE(def->applications.empty())
    << "the refused RemoveApplication emptied the Role's application list";
  EXPECT_EQ(count_applications(*roleConfiguration, NodeId{0, operatorRoleId}, seededApplicationUri), 1u)
    << "the application list must be unchanged after a refused RemoveApplication";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.4.9 L970-971. The Endpoints list is a filter on where a Role's permissions
// apply, so an unprivileged caller who can append to it extends their own reach to endpoints
// the administrator deliberately left out. The refusal is not the whole obligation: a server
// that appends first and authorises afterwards has already widened the Role, and reporting Bad
// afterwards does not narrow it again.
// @verifies AC-SVR-SECADMIN-044-ADDENDPOINT-ADMIN
TEST_F(RbacSeededEndpointNonAdminFixture, AddEndpointRefusedWithoutAdminRightsAndNothingAdded)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddEndpointUnchanged");

  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddEndpointMethod},
              {Variant{endpoint(std::string{intrudedEndpointUrl})}}),
    Status::BadUserAccessDenied);

  auto def = roleConfiguration->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_FALSE(def->endpoints.empty())
    << "the refused AddEndpoint must not have disturbed the seeded endpoint list";
  EXPECT_EQ(count_endpoints(*roleConfiguration, NodeId{0, operatorRoleId}, intrudedEndpointUrl), 0u)
    << "a refused AddEndpoint must not add the endpoint to the Role";
  EXPECT_EQ(count_endpoints(*roleConfiguration, NodeId{0, operatorRoleId}, seededEndpointUrl), 1u)
    << "and must leave the pre-existing entry in place";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.4.10 L997-998. Removal is the dangerous direction on an exclude-list Role:
// taking an endpoint out of the Endpoints list widens where the Role applies rather than
// narrowing it, so an unprivileged caller who can do it grants itself the Role's permissions on
// an endpoint the administrator had ruled out. The endpoint named here is really assigned to the
// Role, so the refusal is authorisation and not Bad_NotFound, and the list must still carry it
// afterwards.
// @verifies AC-SVR-SECADMIN-045-REMOVEENDPOINT-ADMIN
TEST_F(RbacSeededEndpointNonAdminFixture, RemoveEndpointRefusedWithoutAdminRightsAndListUnchanged)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RemoveEndpointUnchanged");

  ASSERT_EQ(count_endpoints(*roleConfiguration, NodeId{0, operatorRoleId}, seededEndpointUrl), 1u)
    << "fixture must seed the endpoint this test tries to remove";

  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorRemoveEndpointMethod},
              {Variant{endpoint(std::string{seededEndpointUrl})}}),
    Status::BadUserAccessDenied);

  auto def = roleConfiguration->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_FALSE(def->endpoints.empty()) << "the refused RemoveEndpoint emptied the Role's endpoint list";
  EXPECT_EQ(count_endpoints(*roleConfiguration, NodeId{0, operatorRoleId}, seededEndpointUrl), 1u)
    << "the endpoint list must be unchanged after a refused RemoveEndpoint";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// Round-4 obligation: the Exclude surface of an AddRole-created Role as a
// client reaches it, with "where the server supports them" established by
// observation instead of taken as an escape.
// ============================================================================

namespace
{

// The two Exclude Properties as NS0 ships them on a well-known Role. Reading these
// establishes, against the server under test rather than by assumption, that the optional
// Properties are something this server supports at all.
constexpr uint32_t operatorApplicationsExcludeProperty =
  static_cast<uint32_t>(VariableId::WellKnownRole_Operator_ApplicationsExclude);
constexpr uint32_t operatorEndpointsExcludeProperty =
  static_cast<uint32_t>(VariableId::WellKnownRole_Operator_EndpointsExclude);

}  // namespace

// Part 18 section 4.2.2 L316-318 read with section 4.5: `ApplicationsExclude` and
// `EndpointsExclude` are the flags that decide whether a Role's Applications / Endpoints list
// is a whitelist or a blacklist, and section 4.5 makes them the only Role Properties a client
// may write directly - the carve-out AC-SVR-SECADMIN-026-ROLE-PROPERTIES-NOT-WRITABLE names as
// its exception. A Role whose Exclude Properties a client cannot reach is a Role the client can
// create and then never configure.
//
// The plausible implementation gets this wrong by creating the Role Object bare. AddRole
// registers the Role and sets both flags in the server's own state, then mirrors them onto
// Property Nodes only where those Nodes already exist - which, on an Object created moments
// earlier with no members, is nowhere; and the write path that carries an Exclude change into
// the Role's filter is wired onto the eight well-known Role Objects alone. The Role then exists
// and answers Browse while offering no way to invert either list, and no assertion made against
// the server's internal state notices, because none of them looks at the Object.
//
// The criterion's "where the server supports them" is therefore established here, not assumed:
// the same session first reads the Properties NS0 ships on the well-known Operator Role and
// confirms each advertises CurrentWrite. A server that offers writable Exclude Properties on its
// well-known Roles supports them; withholding them from the Roles its own AddRole creates is not
// the unsupported case the condition excuses.
// @relation(SVR-SECADMIN-036, scope=function)
// @verifies AC-SVR-SECADMIN-036-ADDROLE-EXCLUDE-PROPERTIES
TEST_F(RbacManagementAdminFixture, AddRoleCreatedRoleExposesItsExcludePropertiesAsWritable)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleExcludeSurface");

  // Antecedent. Both Properties exist on the well-known Operator Role and advertise
  // CurrentWrite, so this server supports them and owes them on the Roles it creates.
  for (uint32_t wellKnownProperty : {operatorApplicationsExcludeProperty, operatorEndpointsExcludeProperty})
  {
    auto supportResp =
      session.attributes().read_sync(read_value(NodeId{0, wellKnownProperty}, AttributeId::AccessLevel));
    ASSERT_THAT(supportResp, ServiceResultIsGood());
    ASSERT_FALSE(supportResp.results().empty());
    ASSERT_THAT(supportResp.results()[0], HasStatus(Status::Good))
      << "well-known Role Exclude Property " << wellKnownProperty << " must be readable";
    const auto* supportedAccess = supportResp.results()[0].value().try_as<uint8_t>();
    ASSERT_NE(supportedAccess, nullptr)
      << "AccessLevel of well-known Role Exclude Property " << wellKnownProperty << " is not a Byte";
    ASSERT_TRUE(AccessLevelType{*supportedAccess}.test(AccessLevelType::Bit::CurrentWrite))
      << "this server supports writable Exclude Properties on its well-known Roles - property "
      << wellKnownProperty << " advertising CurrentWrite is what makes the rest of this test owed";
  }

  const NodeId newRoleId = add_role(session, "ExcludeSurfaceRole", namespace_uri_for_index(1));
  ASSERT_FALSE(newRoleId.is_null()) << "AddRole must return the NodeId of the Role it created";

  for (int index = 0; index < 2; ++index)
  {
    const bool applications = (index == 0);
    const char* propertyName = applications ? "ApplicationsExclude" : "EndpointsExclude";

    // Present. A Browse of the Role Object is the client's only route to a Property whose
    // NodeId the server allocated, so it is also the only honest observation of presence.
    const NodeId propertyId = find_child_node_id(session, newRoleId, propertyName);
    EXPECT_FALSE(propertyId.is_null())
      << propertyName
      << " must be present on the Role AddRole created (Part 18 section 4.2.2 L316-318, section 4.5); "
         "this server carries it on its well-known Roles, so a Role created bare leaves the client no "
         "way to invert the Role's list";
    if (propertyId.is_null())
    {
      // The failure above is recorded; skip only this Property's remaining arms so the sibling
      // Property is still exercised and reported rather than masked by the first miss.
      continue;
    }

    // Read. The value a client reads on a freshly created Role is the blacklist default.
    auto readResp = session.attributes().read_sync(read_value(propertyId));
    ASSERT_THAT(readResp, ServiceResultIsGood());
    ASSERT_FALSE(readResp.results().empty());
    EXPECT_THAT(readResp.results()[0], HasStatus(Status::Good)) << "read of " << propertyName;
    const auto* initial = readResp.results()[0].value().try_as<bool>();
    ASSERT_NE(initial, nullptr) << propertyName << " must read back as a Boolean";
    EXPECT_TRUE(*initial) << "the initial value of " << propertyName
                          << " on an AddRole-created Role shall be TRUE (Part 18 section 4.2.2 L316-318)";

    // Writable, conjunct 1: the Attribute advertises it, so a client that reads before writing
    // is not told the Property is read-only.
    auto accessResp = session.attributes().read_sync(read_value(propertyId, AttributeId::AccessLevel));
    ASSERT_THAT(accessResp, ServiceResultIsGood());
    ASSERT_FALSE(accessResp.results().empty());
    const auto* accessLevel = accessResp.results()[0].value().try_as<uint8_t>();
    ASSERT_NE(accessLevel, nullptr) << "AccessLevel of " << propertyName << " is not a Byte";
    EXPECT_TRUE(AccessLevelType{*accessLevel}.test(AccessLevelType::Bit::CurrentWrite))
      << propertyName << " must advertise CurrentWrite - it is the section 4.5 carve-out from the "
      << "read-only Role Property surface";

    // Writable, conjunct 2: the Write Service accepts it.
    auto writeResp =
      session.attributes().write_sync(WriteRequestBuilder{}.write(propertyId, Variant{false}).build());
    ASSERT_THAT(writeResp, ServiceResultIsGood());
    ASSERT_FALSE(writeResp.results().empty());
    EXPECT_EQ(writeResp.results()[0].as_status(), Status::Good)
      << propertyName << " must accept a direct Write (Part 18 section 4.5)";

    // Writable, conjunct 3: it takes effect where the client can see it ...
    auto readBack = session.attributes().read_sync(read_value(propertyId));
    ASSERT_THAT(readBack, ServiceResultIsGood());
    ASSERT_FALSE(readBack.results().empty());
    const auto* written = readBack.results()[0].value().try_as<bool>();
    ASSERT_NE(written, nullptr) << propertyName << " read-back is not a Boolean";
    EXPECT_FALSE(*written) << "the accepted Write of " << propertyName
                           << " must take effect; a Write that reports Good and leaves the previous "
                              "value is a discarded Write, not a writable Property";

    // ... and where it decides anything: the exclude flag Role evaluation consults when it
    // evaluates the Role's Applications / Endpoints filter. A Property that moves only the
    // Value Attribute leaves the filter on its old polarity and misreports the Role.
    auto def = roleConfiguration->get_role(newRoleId);
    ASSERT_TRUE(def) << "the Role AddRole created must still be registered";
    EXPECT_FALSE(applications ? def->applicationsExclude : def->endpointsExclude)
      << "the accepted Write of " << propertyName
      << " must reach the exclude flag Role evaluation consults, not just the Value Attribute";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SECADMIN-036 - the initial values of an AddRole-created Role's two Exclude
// flags, per flag, in every place this server keeps them.
// ============================================================================

namespace
{

/// Read the Value Attribute of a Boolean Property over the wire into `out`. Records a
/// non-fatal failure and leaves `out` untouched when the read does not yield a Boolean, so a
/// read that fails can never silently satisfy the caller's expectation about the value.
bool read_boolean_value(Session& session, const NodeId& nodeId, const char* what, bool& out)
{
  auto resp = session.attributes().read_sync(read_value(nodeId));
  EXPECT_THAT(resp, ServiceResultIsGood()) << "read of " << what;
  if (resp.results().empty())
  {
    ADD_FAILURE() << "read of " << what << " returned no results";
    return false;
  }
  EXPECT_THAT(resp.results()[0], HasStatus(Status::Good)) << "read of " << what;
  const auto* value = resp.results()[0].value().try_as<bool>();
  if (value == nullptr)
  {
    ADD_FAILURE() << what << " must read back as a Boolean";
    return false;
  }
  out = *value;
  return true;
}

}  // namespace

// Part 18 section 4.2.2 L316-318. The duty is on the initial VALUES: both exclude flags of a Role
// AddRole has just created start TRUE. That is the "blacklist over an empty list" pairing the
// requirement's STATEMENT turns on - a fresh Role reachable from every Endpoint and every
// Application, where Exclude FALSE over an empty list would leave it reachable from none.
//
// The clause's antecedent is per-Object - "if the optional Properties ... are available on the
// Role Object created with this Method" - and both Properties carry the Optional modelling rule
// on NS0 `RoleType` (Table 4). Neither their presence on the created Object nor their
// writability is owed by this obligation: presence is its condition, and the section 4.5 Write
// carve-out belongs to SVR-SECADMIN-026, whose own NOTES place Exclude writability outside its
// scope.
//
// So the values are asserted wherever this server keeps them, one flag at a time. Unconditionally
// in the exclude state the Role evaluator's Application and Endpoint filters consult, because a
// handler that seeds one flag and leaves the other zero-initialised produces a Role that matches
// nothing on that side, and only a per-flag assertion sees it. Then, on the wire for whichever
// Property the created Object actually carries - the arm the antecedent switches on.
// @relation(SVR-SECADMIN-036, scope=function)
// @verifies AC-SVR-SECADMIN-036-ADDROLE-EXCLUDE-PROPERTIES
TEST_F(RbacManagementAdminFixture, AddRoleCreatedRoleStartsWithBothExcludeFlagsTrue)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AddRoleExcludeDefaults");

  const NodeId newRoleId = add_role(session, "ExcludeDefaultsRole", namespace_uri_for_index(1));
  ASSERT_FALSE(newRoleId.is_null()) << "AddRole must return the NodeId of the Role it created";

  // Non-vacuity for the wire call: the Role the Call reports is the Role the server registered.
  auto def = roleConfiguration->get_role(newRoleId);
  ASSERT_TRUE(def) << "AddRole must register the new Role in the live RoleConfiguration";
  EXPECT_TRUE(def->applicationsExclude)
    << "the initial value of ApplicationsExclude on an AddRole-created Role shall be TRUE (Part 18 "
       "section 4.2.2 L316-318)";
  EXPECT_TRUE(def->endpointsExclude)
    << "the initial value of EndpointsExclude on an AddRole-created Role shall be TRUE (Part 18 "
       "section 4.2.2 L316-318)";

  // The address-space arm under the spec's own antecedent: an absent Property is the Optional
  // modelling rule being exercised, not a breach, but a present one owes the value TRUE.
  for (const char* propertyName : {"ApplicationsExclude", "EndpointsExclude"})
  {
    const NodeId propertyId = find_child_node_id(session, newRoleId, propertyName);
    if (propertyId.is_null())
    {
      continue;
    }
    bool value = false;
    ASSERT_TRUE(read_boolean_value(session, propertyId, propertyName, value));
    EXPECT_TRUE(value) << "where the created Role Object carries " << propertyName
                       << ", its initial value shall be TRUE";
  }

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// Round-7: the server-side certificate-validation clauses of the Security
// Administration set - SVR-SECADMIN-006 (wire masking), -010 (re-validation at
// every token renewal), -011 (re-validation on a trust-list update), -022
// (chain monotonicity) and -024 (keyUsage / extendedKeyUsage /
// basicConstraints).
//
// They belong on this fixture chain because `ComplianceRoleBasedSecurity` ->
// `ComplianceSecured` is the only scaffolding here that owns a REAL server-side
// PKI: the server's own `CertificateStore` (`mServerCertStore` - the very object
// `SecurityPolicy::validate_certificate_async` consults on every OPN), the
// `Crypto` provider that allocated both parties' certificates, and a live endpoint
// to present a certificate to. Nothing below is stubbed: every shaped
// certificate is allocated through the production `Crypto` and presented to the
// running server over a real SecureChannel, and every verdict asserted is the
// one the server reached on its own.
// ============================================================================

namespace
{

using CSCTA = ua::client::SecureChannelTestAccess;

/// What became of a deliberately triggered SecurityToken renewal.
enum class RenewOutcome
{
  Renewed,  ///< the token advanced - the server accepted the renewal
  Disconnected,  ///< the channel closed - the server refused the renewal
  TimedOutStillOpen  ///< neither, within the bound
};

/// The channel's current SecurityToken id, read on the channel strand. A fresh non-zero id is
/// adopted per accepted token, so a change in this value IS an accepted renewal.
uint32_t read_token_id(ua::client::SecureChannel& channel)
{
  return CSCTA::on_strand(channel, [](auto& guard) { return guard.channel_token_id(); });
}

/// Drive one OPN-Renew round trip through the channel's own renewal entry point - the controllable
/// interface, not a wall-clock timer - and wait, bounded, for the real exchange with the in-process
/// server to resolve. The renewal is an asymmetric (OPN) message, so the server re-runs its
/// certificate validation on it; the outcome therefore reports the server's renewal-time verdict.
RenewOutcome trigger_renewal_and_wait(ua::client::SecureChannel& channel, uint32_t previousTokenId,
  std::chrono::milliseconds timeout = std::chrono::seconds{10})
{
  CSCTA::on_strand(channel,
    [](auto& guard)
    {
      guard.handle_token_renewal();
      return 0;
    });

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (!channel.is_open())
    {
      return RenewOutcome::Disconnected;
    }
    const uint32_t token = read_token_id(channel);
    if (token != previousTokenId && token != 0)
    {
      return RenewOutcome::Renewed;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
  }
  return RenewOutcome::TimedOutStillOpen;
}

}  // namespace

// Part 4 section 6.1.3 Table 106 says, row by row, what the Server reports back when a check fails. The trust
// row: "If this check fails on the Server side, the error Bad_SecurityChecksFailed shall be reported back to
// the Client." The Validity Period row says no such thing, and Table 12 lists Bad_CertificateTimeInvalid
// among the OpenSecureChannel results, so an expired certificate is reported as such. That is no oracle for
// a stranger: the steps are applied in Table 106's order and the trust row comes first, so a certificate
// whose issuer the server does not trust is refused as untrusted whatever else is wrong with it - which is
// the premise the third case below pins.
// @verifies AC-SVR-SECADMIN-006-CHECKS-FAILED-SUBSTITUTED
TEST_F(RbacServerCertificateValidation, CertificateRejectionsReachTheClientAsTable106Reports)
{
  const auto trustedCaKeys = new_rsa_keys(2048);
  const auto strangerCaKeys = new_rsa_keys(2048);
  ASSERT_TRUE(trustedCaKeys);
  ASSERT_TRUE(strangerCaKeys);

  const auto trustedCa =
    allocate(root_ca_params(trustedCaKeys, "6001", "SECADMIN-006 Trusted CA"), "trusted CA");
  const auto strangerCa =
    allocate(root_ca_params(strangerCaKeys, "6002", "SECADMIN-006 Stranger CA"), "stranger CA");
  ASSERT_TRUE(trustedCa);
  ASSERT_TRUE(strangerCa);
  // Only one of the two CAs is trusted; the stranger is deliberately left out of the trust list.
  mServerCertStore->add_to_trusted_certificates_sync(trustedCa);

  // Reason 1 - trust. A fully conformant, in-date leaf whose issuer the server does not trust.
  const auto untrustedKeys = new_rsa_keys(2048);
  ASSERT_TRUE(untrustedKeys);
  const auto untrustedLeaf =
    allocate(conformant_leaf_params(
               strangerCa, strangerCaKeys, untrustedKeys, "6003", "SECADMIN-006 Untrusted Leaf", "untrusted"),
      "untrusted leaf");
  ASSERT_TRUE(untrustedLeaf);

  // Reason 2 - validity. Issued by the CA the server DOES trust, so the trust row passes and only
  // the validity row can refuse it. A different row of Table 106 from reason 1, by construction.
  const auto expiredKeys = new_rsa_keys(2048);
  ASSERT_TRUE(expiredKeys);
  auto expiredParams = conformant_leaf_params(
    trustedCa, trustedCaKeys, expiredKeys, "6004", "SECADMIN-006 Expired Leaf", "expired");
  expiredParams.from = DateTime{DateTime::now().value() - std::chrono::days{30}};
  expiredParams.to = DateTime{DateTime::now().value() - std::chrono::days{1}};
  const auto expiredLeaf = allocate(expiredParams, "expired leaf");
  ASSERT_TRUE(expiredLeaf);

  // The premise the masking obligation rests on: these two certificates really do fail for DIFFERENT
  // internal reasons. Read those reasons off the server's own store - the object the OPN path
  // validates against - so that identical wire codes below are masking and not coincidence.
  const auto untrustedReason = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(untrustedLeaf, {}, std::nullopt));
  const auto expiredReason = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(expiredLeaf, {}, std::nullopt));
  ASSERT_TRUE(untrustedReason.is_bad()) << "the untrusted leaf must fail the server's own validation";
  ASSERT_TRUE(expiredReason.is_bad()) << "the expired leaf must fail the server's own validation";
  ASSERT_NE(untrustedReason.status_code().as_status(), expiredReason.status_code().as_status())
    << "the two certificates must fail for DIFFERENT reasons, otherwise identical wire codes would "
       "prove nothing about substitution";

  EXPECT_EQ(channel_status_as(untrustedLeaf, untrustedKeys, "untrusted"), Status::BadSecurityChecksFailed)
    << "the trust row: an untrusted client certificate is reported as Bad_SecurityChecksFailed";
  EXPECT_EQ(channel_status_as(expiredLeaf, expiredKeys, "expired"), Status::BadCertificateTimeInvalid)
    << "the validity row carries no masking instruction: a trusted but expired certificate is reported as "
       "Bad_CertificateTimeInvalid";

  // A stranger's certificate that is ALSO expired is still refused by the trust row first, so the peer
  // learns nothing about which of its defects the server found.
  const auto strangerExpiredKeys = new_rsa_keys(2048);
  ASSERT_TRUE(strangerExpiredKeys);
  auto strangerExpiredParams = conformant_leaf_params(strangerCa,
    strangerCaKeys,
    strangerExpiredKeys,
    "6006",
    "SECADMIN-006 Stranger Expired Leaf",
    "stranger-expired");
  strangerExpiredParams.from = DateTime{DateTime::now().value() - std::chrono::days{30}};
  strangerExpiredParams.to = DateTime{DateTime::now().value() - std::chrono::days{1}};
  const auto strangerExpiredLeaf = allocate(strangerExpiredParams, "stranger's expired leaf");
  ASSERT_TRUE(strangerExpiredLeaf);
  EXPECT_EQ(channel_status_as(strangerExpiredLeaf, strangerExpiredKeys, "stranger-expired"),
    Status::BadSecurityChecksFailed)
    << "an untrusted certificate must not reveal that it is also expired";

  // Non-vacuity: the same helper, the same endpoint, a conformant leaf under the trusted CA opens a
  // channel. Without this the two refusals above could be a client that cannot connect at all.
  const auto goodKeys = new_rsa_keys(2048);
  ASSERT_TRUE(goodKeys);
  const auto goodLeaf = allocate(
    conformant_leaf_params(trustedCa, trustedCaKeys, goodKeys, "6005", "SECADMIN-006 Good Leaf", "good"),
    "conformant leaf");
  ASSERT_TRUE(goodLeaf);
  EXPECT_EQ(channel_status_as(goodLeaf, goodKeys, "good"), Status::Good)
    << "a conformant leaf under the trusted CA must be admitted - this is what makes the two "
       "refusals above attributable to the certificates and not to the harness";
}

// Part 4 section 6.1.7: "ApplicationInstanceCertificates verification shall be executed every time the
// SecurityToken is renewed for a SecureChannel." The plausible implementation validates once, at
// channel open, and treats the renewal as a pure key-derivation step - it already knows this peer.
// The consequence is that revocation never reaches an established connection: a server-to-server
// link stays up on a revoked certificate for as long as nobody reconnects, which for a long-lived
// link is indefinitely.
// @verifies AC-SVR-SECADMIN-010-REVALIDATE-ON-RENEW
TEST_F(RbacServerCertificateValidation, ClientCertificateIsRevalidatedAtEverySecurityTokenRenewal)
{
  // A peer identity allocated here, so this test holds the private key that must sign the revocation
  // list. Self-signed, so the certificate is its own issuer and its own CRL issuer.
  const auto peerKeys = new_rsa_keys(2048);
  ASSERT_TRUE(peerKeys);
  auto peerParams = root_ca_params(peerKeys, "6101", "SECADMIN-010 Peer");
  peerParams.basicConstraint.pathLength = 0;
  peerParams.keyUsage.nonRepudiation = true;
  peerParams.keyUsage.keyEncipherment = true;
  peerParams.keyUsage.dataEncipherment = true;
  peerParams.keyUsage.clientAuth = true;
  peerParams.subjectAlternateName.uris.push_back(identity_uri("peer"));
  peerParams.subjectAlternateName.hostnames.push_back("localhost");
  const auto peerCert = allocate(peerParams, "peer certificate");
  ASSERT_TRUE(peerCert);
  mServerCertStore->add_to_trusted_certificates_sync(peerCert);

  auto opened = open_channel_as(peerCert, peerKeys, "peer");
  ASSERT_TRUE(opened.is_good()) << "precondition: the peer certificate is trusted at this point, so the "
                                   "channel must open; got "
                                << opened.status_code().value();
  auto channel = std::move(opened).value();

  // Control. The renewal round trip works against this server while the certificate is good, so a
  // refusal below is the certificate and not a renewal path that never completes.
  const uint32_t firstToken = read_token_id(channel);
  ASSERT_NE(firstToken, 0u) << "precondition: an open channel must hold a SecurityToken";
  ASSERT_EQ(trigger_renewal_and_wait(channel, firstToken), RenewOutcome::Renewed)
    << "precondition: a renewal on a still-valid certificate must be accepted";
  const uint32_t secondToken = read_token_id(channel);
  ASSERT_NE(secondToken, firstToken) << "precondition: an accepted renewal adopts a new token";

  // Revoke - on the server's own store, and WITHOUT touching the trust list, so the only thing that
  // can refuse the next renewal is a re-run of the validation the server did at open.
  mServerCertStore->set_validation_options(
    TrustListValidationOptions{TrustListValidationOptions::Bit::CheckRevocationStatusOffline});
  auto crl = mCrypto->try_create_crl_sync(peerCert, peerKeys, {peerCert->serial_number()});
  ASSERT_TRUE(crl.is_good()) << "the test must be able to revoke its own certificate: "
                             << crl.status_code().value();
  mServerCertStore->add_to_trusted_crls_sync(std::move(crl).value());

  EXPECT_EQ(trigger_renewal_and_wait(channel, secondToken), RenewOutcome::Disconnected)
    << "the renewal of a channel whose certificate has been revoked must be refused (Part 4 section 6.1.7); "
       "an accepted renewal means the open-time verdict was cached";

  // Falsifiability of the stimulus: the certificate is still in the trust list, so the refusal above
  // can only be the renewal-time re-validation and not an edit to the trust list.
  auto trusted = mServerCertStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trusted.is_good());
  const auto trustedList = std::move(trusted).value();
  ASSERT_FALSE(trustedList.empty()) << "the trust list must not have been emptied by this test";
  bool stillTrusted = false;
  for (const auto& entry : trustedList)
  {
    if (entry && entry->serial_number() == peerCert->serial_number())
    {
      stillTrusted = true;
    }
  }
  EXPECT_TRUE(stillTrusted) << "the revoked certificate must still be in the trust list - the renewal "
                               "was refused on revocation grounds, not because trust was withdrawn";
}

// Part 4 section 6.1.7 states two things about a trust-list change, and only one of them is mandatory:
// verification "shall be executed every time the SecurityToken is renewed", while applications
// "may do additional verifications between SecurityToken renews e.g. if the trust list is updated".
// SVR-SECADMIN-011 derives from the permissive half alone, so what an administrator is owed is that
// the re-validation at the next renewal reads the CURRENT trust list: withdrawing trust from a live
// peer must refuse it there. The plausible implementation pins the peer's trust decision to the
// channel when it opens and re-checks only dates and revocation at renewal, so an administrator who
// withdraws trust never reaches the established connection at all.
//
// The trust-withdrawal counterpart of the revocation case above, and deliberately disjoint from it:
// that test leaves the certificate trusted and revokes it, this one leaves it unrevoked and takes
// its trust away, so neither refusal can be running on the other's mechanism. The trusted CRL set is
// carried across the edit unchanged, which leaves the peer's presence in the trust list as the only
// difference between the renewal accepted below and the renewal refused after it.
// @verifies AC-SVR-SECADMIN-011-REVALIDATE-ON-TRUSTLIST-UPDATE
TEST_F(RbacServerCertificateValidation, TrustListWithdrawalIsHonouredAtTheNextSecurityTokenRenewal)
{
  // Self-signed, so withdrawing this one certificate withdraws the peer's whole trust path.
  const auto peerKeys = new_rsa_keys(2048);
  ASSERT_TRUE(peerKeys);
  auto peerParams = root_ca_params(peerKeys, "6111", "SECADMIN-011 Peer");
  peerParams.basicConstraint.pathLength = 0;
  peerParams.keyUsage.nonRepudiation = true;
  peerParams.keyUsage.keyEncipherment = true;
  peerParams.keyUsage.dataEncipherment = true;
  peerParams.keyUsage.clientAuth = true;
  peerParams.subjectAlternateName.uris.push_back(identity_uri("trustpeer"));
  peerParams.subjectAlternateName.hostnames.push_back("localhost");
  const auto peerCert = allocate(peerParams, "peer certificate");
  ASSERT_TRUE(peerCert);
  mServerCertStore->add_to_trusted_certificates_sync(peerCert);

  auto opened = open_channel_as(peerCert, peerKeys, "trustpeer");
  ASSERT_TRUE(opened.is_good()) << "precondition: the peer certificate is trusted at this point, so the "
                                   "channel must open; got "
                                << opened.status_code().value();
  auto channel = std::move(opened).value();

  // Control. A renewal round trip completes against this server while the peer is still trusted, so
  // the refusal below is the trust list and not a renewal path that never completes.
  const uint32_t firstToken = read_token_id(channel);
  ASSERT_NE(firstToken, 0u) << "precondition: an open channel must hold a SecurityToken";
  ASSERT_EQ(trigger_renewal_and_wait(channel, firstToken), RenewOutcome::Renewed)
    << "precondition: a renewal on a still-trusted certificate must be accepted";
  const uint32_t secondToken = read_token_id(channel);
  ASSERT_NE(secondToken, firstToken) << "precondition: an accepted renewal adopts a new token";

  // The administrative action: this peer alone leaves the trust list, and the trusted CRL set is
  // written back exactly as it was read. Everything else the server trusts stays, so the refusal
  // cannot be a server left with no trust material at all.
  auto trustedBefore = mServerCertStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trustedBefore.is_good()) << trustedBefore.status_code().value();
  auto crlsBefore = mServerCertStore->try_get_trusted_crls_sync();
  ASSERT_TRUE(crlsBefore.is_good()) << crlsBefore.status_code().value();
  const auto trustedList = std::move(trustedBefore).value();
  ua::CertificateList remaining;
  for (const auto& entry : trustedList)
  {
    if (entry && entry->serial_number() != peerCert->serial_number())
    {
      remaining.push_back(entry);
    }
  }
  ASSERT_EQ(remaining.size() + 1, trustedList.size())
    << "precondition: exactly the peer's certificate must be the one withdrawn";
  auto replaced = mServerCertStore->try_replace_trusted_certificates_sync(
    std::move(remaining), std::move(crlsBefore).value());
  ASSERT_TRUE(replaced.is_good()) << "the trust list must be replaceable: " << replaced.status_code().value();
  auto trustedAfter = mServerCertStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trustedAfter.is_good());
  for (const auto& entry : std::move(trustedAfter).value())
  {
    ASSERT_FALSE(entry && entry->serial_number() == peerCert->serial_number())
      << "precondition: the peer certificate really is out of the server's trust list now";
  }

  EXPECT_EQ(trigger_renewal_and_wait(channel, secondToken), RenewOutcome::Disconnected)
    << "the renewal of a channel whose certificate has left the trust list must be refused (Part 4 "
       "section 6.1.7) - an accepted renewal means the open-time trust decision was cached on the channel";

  (void)channel.try_close_sync();
}

// Part 6 section 6.1: "the key length of issued Certificates shall be less than or equal to the key length
// of the issuer Certificate" and "Each Issuer in a chain shall have an algorithm that is the same or
// higher priority than any Certificate it issues." Every certificate in both chains below is
// individually valid - correct signature, in date, conformant extensions, chaining to a trusted root
// - which is exactly why the check is easy to omit: a validator that walks the chain one certificate
// at a time never compares a link with the one above it, and a 4096-bit leaf under a 2048-bit issuer
// is forgeable at the issuer while looking strong at the leaf.
//
// The verdicts are taken from the server's own `CertificateStore` - the object
// `SecurityPolicy::validate_certificate_async` hands every OPN certificate to, with the server's own
// trust material and validation options, so this is the server's real decision on these chains.
// @verifies AC-SVR-SECADMIN-022-CHAIN-MONOTONICITY
TEST_F(RbacServerCertificateValidation, ChainKeyLengthAndSignatureStrengthDoNotIncreaseTowardsTheLeaf)
{
  const auto caKeys = new_rsa_keys(2048);
  ASSERT_TRUE(caKeys);
  const auto ca = allocate(root_ca_params(caKeys, "6201", "SECADMIN-022 CA"), "issuing CA");
  ASSERT_TRUE(ca);
  mServerCertStore->add_to_trusted_certificates_sync(ca);

  // Control: same CA, same algorithm, leaf key no longer than the issuer's - a monotonic chain,
  // accepted. This is what makes the two refusals below attributable to the monotonicity invariants
  // rather than to anything else about the chain or the harness.
  const auto matchedKeys = new_rsa_keys(2048);
  ASSERT_TRUE(matchedKeys);
  const auto matchedLeaf =
    allocate(conformant_leaf_params(ca, caKeys, matchedKeys, "6202", "SECADMIN-022 Matched Leaf", "matched"),
      "matched-strength leaf");
  ASSERT_TRUE(matchedLeaf);
  const auto matched = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(matchedLeaf, {}, std::nullopt));
  EXPECT_TRUE(matched.is_good()) << "a chain whose key lengths and algorithms are monotonic must be "
                                    "accepted; got "
                                 << matched.status_code().value();

  // (a) Key length increases towards the leaf: 4096-bit leaf under a 2048-bit issuer.
  const auto longerKeys = new_rsa_keys(4096);
  ASSERT_TRUE(longerKeys);
  const auto longerLeaf =
    allocate(conformant_leaf_params(ca, caKeys, longerKeys, "6203", "SECADMIN-022 Longer Leaf", "longer"),
      "longer-key leaf");
  ASSERT_TRUE(longerLeaf);
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(longerLeaf, {}, std::nullopt))
      .is_bad())
    << "a leaf whose key is longer than its issuer's must be refused (Part 6 section 6.1) - the chain is "
       "only "
       "as strong as the issuer that can forge it";

  // (b) Signature strength increases towards the leaf: a SHA-1-signed CA issuing a SHA-256 leaf.
  const auto weakCaKeys = new_rsa_keys(2048);
  ASSERT_TRUE(weakCaKeys);
  const auto weakCa = allocate(
    root_ca_params(weakCaKeys, "6204", "SECADMIN-022 SHA1 CA", CertificateSignatureAlgorithm::RsaPkcs15Sha1),
    "SHA-1 signed CA");
  ASSERT_TRUE(weakCa);
  mServerCertStore->add_to_trusted_certificates_sync(weakCa);
  const auto strongKeys = new_rsa_keys(2048);
  ASSERT_TRUE(strongKeys);
  const auto strongLeaf = allocate(
    conformant_leaf_params(weakCa, weakCaKeys, strongKeys, "6205", "SECADMIN-022 Strong Leaf", "strong"),
    "SHA-256 leaf under a SHA-1 CA");
  ASSERT_TRUE(strongLeaf);
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(strongLeaf, {}, std::nullopt))
      .is_bad())
    << "a chain whose issuer signature algorithm is weaker than the certificate it issues must be "
       "refused (Part 6 section 6.1) - the SHA-1 issuer is the forgeable link";
}

// Part 6 section 6.2.2 Table 43: for RSA keys the keyUsage "shall include digitalSignature, nonRepudiation,
// keyEncipherment and dataEncipherment", the extendedKeyUsage "shall specify serverAuth and/or
// clientAuth", and "The cA flag shall be FALSE for ApplicationInstance Certificates issued by a CA".
// The plausible implementation checks digitalSignature alone, because that is the bit the handshake
// signature actually needs, and lets the rest through: the certificate verifies, so it is accepted.
// The basicConstraints case is the one with teeth - a CA-issued leaf that declares itself a CA can
// allocate identities that chain to a certificate the server already trusts.
//
// The verdicts are taken from the server's own `CertificateStore`, the object the OPN path validates
// every incoming certificate against. Presenting these certificates over a channel instead would
// test the CLIENT first: this SDK's client refuses to USE an own certificate whose keyUsage is short
// of Table 43 (`validate_own_application_certificate`), which is a separate, client-side obligation
// and would mask the server-side one under test here.
// @verifies AC-SVR-SECADMIN-024-KEYUSAGE-ENFORCED
TEST_F(RbacServerCertificateValidation, KeyUsageExtendedKeyUsageAndBasicConstraintsAreEnforced)
{
  const auto caKeys = new_rsa_keys(2048);
  ASSERT_TRUE(caKeys);
  const auto ca = allocate(root_ca_params(caKeys, "6301", "SECADMIN-024 CA"), "issuing CA");
  ASSERT_TRUE(ca);
  mServerCertStore->add_to_trusted_certificates_sync(ca);

  // Control: the same CA, the same chain, every Table 43 field correct - accepted. Each refusal
  // below differs from this certificate in exactly one extension field.
  const auto conformantKeys = new_rsa_keys(2048);
  ASSERT_TRUE(conformantKeys);
  const auto conformantLeaf = allocate(
    conformant_leaf_params(ca, caKeys, conformantKeys, "6302", "SECADMIN-024 Conformant Leaf", "conformant"),
    "conformant leaf");
  ASSERT_TRUE(conformantLeaf);
  const auto conformant = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(conformantLeaf, {}, std::nullopt));
  EXPECT_TRUE(conformant.is_good()) << "a certificate satisfying Table 43 in full must be accepted; got "
                                    << conformant.status_code().value();

  // (a) keyUsage omits keyEncipherment.
  const auto noEnciphermentKeys = new_rsa_keys(2048);
  ASSERT_TRUE(noEnciphermentKeys);
  auto noEnciphermentParams = conformant_leaf_params(
    ca, caKeys, noEnciphermentKeys, "6303", "SECADMIN-024 No KeyEncipherment", "nokeyenc");
  noEnciphermentParams.keyUsage.keyEncipherment = false;
  const auto noEnciphermentLeaf = allocate(noEnciphermentParams, "leaf without keyEncipherment");
  ASSERT_TRUE(noEnciphermentLeaf);
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(noEnciphermentLeaf, {}, std::nullopt))
      .is_bad())
    << "an RSA certificate whose keyUsage omits keyEncipherment must be refused (Part 6 section 6.2.2 "
       "Table 43); checking digitalSignature alone accepts it";

  // (b) extendedKeyUsage omits both serverAuth and clientAuth.
  const auto noEkuKeys = new_rsa_keys(2048);
  ASSERT_TRUE(noEkuKeys);
  auto noEkuParams = conformant_leaf_params(ca, caKeys, noEkuKeys, "6304", "SECADMIN-024 No EKU", "noeku");
  noEkuParams.keyUsage.clientAuth = false;
  noEkuParams.keyUsage.serverAuth = false;
  const auto noEkuLeaf = allocate(noEkuParams, "leaf without an extendedKeyUsage purpose");
  ASSERT_TRUE(noEkuLeaf);
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(noEkuLeaf, {}, std::nullopt))
      .is_bad())
    << "a certificate whose extendedKeyUsage specifies neither serverAuth nor clientAuth must be "
       "refused (Part 6 section 6.2.2 Table 43)";

  // (c) basicConstraints marks the CA-ISSUED leaf as a CA. The Table 43 backward-interoperability
  // allowance for cA=TRUE is scoped to SELF-SIGNED certificates (SVR-SECADMIN-024 restates it that
  // way); for a CA-issued ApplicationInstance Certificate the flag shall be FALSE.
  const auto caFlagKeys = new_rsa_keys(2048);
  ASSERT_TRUE(caFlagKeys);
  auto caFlagParams =
    conformant_leaf_params(ca, caKeys, caFlagKeys, "6305", "SECADMIN-024 CA Flag Leaf", "caflag");
  caFlagParams.basicConstraint.cA = true;
  const auto caFlagLeaf = allocate(caFlagParams, "CA-issued leaf marked as a CA");
  ASSERT_TRUE(caFlagLeaf);
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(caFlagLeaf, {}, std::nullopt))
      .is_bad())
    << "a CA-issued ApplicationInstance Certificate whose basicConstraints marks it a CA must be "
       "refused (Part 6 section 6.2.2 Table 43) - accepting it lets the peer allocate identities that chain "
       "to "
       "a certificate this server already trusts";
}

// ============================================================================
// Round-8: the two-list trust model (SVR-SECADMIN-009), the RoleType access
// gate (SVR-SECADMIN-025) and the three-predicate Role grant
// (SVR-SECADMIN-027).
// ============================================================================

// Part 4 section 6.1.3, read with SVR-SECADMIN-009's own statement of the model: the server's trust
// configuration is TWO lists. Trusted Certificates are trust anchors; Issuer Certificates are chain
// -building material and nothing else. The plausible implementation keeps one list, because a single
// X509_STORE is simpler and every chain that used to build still builds. What it silently adds is
// trust: every intermediate CA an administrator supplied only so that chains could be completed
// becomes an acceptable peer identity in its own right, and so does everything that CA ever signed.
//
// Both halves of the observation are asserted. The issuer list really is consulted, so a leaf under
// an intermediate that appears ONLY in the issuer list is accepted through the chain to a trusted
// root; and issuer-list membership on its own confers nothing, so a CA sitting in the issuer list is
// refused when it is presented as a peer certificate, as is a leaf beneath it. The verdicts come
// from the server's own `CertificateStore` - the object `SecurityPolicy::validate_certificate_async`
// hands every OPN certificate to, with the server's own trust material.
// @verifies AC-SVR-SECADMIN-009-TWO-TRUST-LISTS
TEST_F(RbacServerCertificateValidation, IssuerListBuildsChainsButConfersNoTrustOfItsOwn)
{
  // Chain 1 - a trusted root, an intermediate that will live in the issuer list only, and a leaf
  // beneath the intermediate. Nothing but the issuer list can complete this chain.
  const auto rootKeys = new_rsa_keys(2048);
  ASSERT_TRUE(rootKeys);
  const auto root = allocate(root_ca_params(rootKeys, "6401", "SECADMIN-009 Root CA"), "root CA");
  ASSERT_TRUE(root);

  const auto intermediateKeys = new_rsa_keys(2048);
  ASSERT_TRUE(intermediateKeys);
  auto intermediateParams = root_ca_params(intermediateKeys, "6402", "SECADMIN-009 Intermediate CA");
  intermediateParams.issuer = root;
  intermediateParams.issuerKeys = rootKeys;
  const auto intermediate = allocate(intermediateParams, "intermediate CA");
  ASSERT_TRUE(intermediate);

  const auto chainLeafKeys = new_rsa_keys(2048);
  ASSERT_TRUE(chainLeafKeys);
  const auto chainLeaf =
    allocate(conformant_leaf_params(
               intermediate, intermediateKeys, chainLeafKeys, "6403", "SECADMIN-009 Chain Leaf", "chainleaf"),
      "leaf under the intermediate CA");
  ASSERT_TRUE(chainLeaf);

  // Chain 2 - a CA that is only ever chain-building material, and a leaf beneath it. No part of this
  // chain reaches a trust anchor, so nothing in it may be accepted.
  const auto strangerKeys = new_rsa_keys(2048);
  ASSERT_TRUE(strangerKeys);
  const auto stranger =
    allocate(root_ca_params(strangerKeys, "6404", "SECADMIN-009 Stranger CA"), "stranger CA");
  ASSERT_TRUE(stranger);

  const auto strangerLeafKeys = new_rsa_keys(2048);
  ASSERT_TRUE(strangerLeafKeys);
  const auto strangerLeaf = allocate(
    conformant_leaf_params(
      stranger, strangerKeys, strangerLeafKeys, "6405", "SECADMIN-009 Stranger Leaf", "strangerleaf"),
    "leaf under the stranger CA");
  ASSERT_TRUE(strangerLeaf);

  mServerCertStore->add_to_trusted_certificates_sync(root);
  mServerCertStore->add_to_issuer_certificates_sync(intermediate);
  mServerCertStore->add_to_issuer_certificates_sync(stranger);

  // The premise: the two CAs really are in the ISSUER list and really are absent from the TRUSTED
  // list. Without this the refusals below could be certificates the store never received.
  auto issuerResult = mServerCertStore->try_get_issuer_certificates_sync();
  ASSERT_TRUE(issuerResult.is_good()) << issuerResult.status_code().value();
  const auto issuerList = std::move(issuerResult).value();
  ASSERT_FALSE(issuerList.empty()) << "the issuer list must not be empty - nothing below would mean anything";
  bool intermediateIsIssuer = false;
  bool strangerIsIssuer = false;
  for (const auto& entry : issuerList)
  {
    if (entry && entry->serial_number() == intermediate->serial_number())
    {
      intermediateIsIssuer = true;
    }
    if (entry && entry->serial_number() == stranger->serial_number())
    {
      strangerIsIssuer = true;
    }
  }
  ASSERT_TRUE(intermediateIsIssuer) << "the intermediate CA must be in the server's issuer list";
  ASSERT_TRUE(strangerIsIssuer) << "the stranger CA must be in the server's issuer list";

  auto trustedResult = mServerCertStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trustedResult.is_good()) << trustedResult.status_code().value();
  const auto trustedList = std::move(trustedResult).value();
  ASSERT_FALSE(trustedList.empty()) << "the trusted list must not be empty - the root was just added to it";
  for (const auto& entry : trustedList)
  {
    ASSERT_FALSE(entry && entry->serial_number() == intermediate->serial_number())
      << "adding a certificate to the issuer list must not put it in the trusted list - the lists are "
         "kept separate";
    ASSERT_FALSE(entry && entry->serial_number() == stranger->serial_number())
      << "adding a certificate to the issuer list must not put it in the trusted list - the lists are "
         "kept separate";
  }

  // Conjunct 1 - the issuer list IS consulted, for chain building. The only path from this leaf to a
  // trust anchor runs through the intermediate, and the intermediate is in the issuer list alone.
  const auto chainVerdict = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(chainLeaf, {}, std::nullopt));
  EXPECT_TRUE(chainVerdict.is_good())
    << "a leaf whose issuing CA is in the issuer list and whose root is trusted must be accepted through "
       "the chain (Part 4 section 6.1.3); got "
    << chainVerdict.status_code().value();

  // Conjunct 2 - and the issuer list confers no trust of its own. The stranger CA is chain-building
  // material; presented as a peer certificate it is a stranger, and a merged single list is exactly
  // what would accept it.
  EXPECT_TRUE(mServerCertStore
                ->try_validate_certificate_sync(ua::test::make_validation_request(stranger, {}, std::nullopt))
                .is_bad())
    << "a CA must not be accepted as a peer merely because it appears in the issuer list - an issuer is "
       "trusted to sign, not to connect";
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(strangerLeaf, {}, std::nullopt))
      .is_bad())
    << "nor may issuer-list membership make the CA's subtree trusted - no certificate in this chain "
       "reaches a trust anchor";
}

namespace
{

// The `Identities` Property of the well-known Operator Role - one of the three Method-mutated
// Properties Part 18 section 4.4 locks down, and the one used here as the read/write probe.
constexpr uint32_t operatorIdentitiesProperty =
  static_cast<uint32_t>(VariableId::WellKnownRole_Operator_Identities);

/// True iff a Read of `nodeId`'s Value Attribute was refused - the service refused it, it produced
/// no result at all, or the per-operation status is Bad. A DataValue with no status is a Good read,
/// so an absent status counts as disclosure, not as refusal.
bool read_value_refused(Session& session, const NodeId& nodeId)
{
  auto resp = session.attributes().read_sync(read_value(nodeId));
  if (!resp.response_header().service_result().is_good())
  {
    return true;
  }
  if (resp.results().empty())
  {
    return true;
  }
  const auto& status = resp.results()[0].status();
  return status.has_value() && !status.value().is_good();
}

/// True iff a direct Attribute Write of an empty structure array to `nodeId` was refused. The value
/// is correctly typed for the Role Properties so that a refusal is the access gate and not a type
/// mismatch the server would have rejected from anybody.
bool direct_write_refused(Session& session, const NodeId& nodeId)
{
  auto resp = session.attributes().write_sync(
    WriteRequestBuilder{}.write(nodeId, Variant{Array<RefStructure<Structure>>{}}).build());
  if (!resp.response_header().service_result().is_good())
  {
    return true;
  }
  if (resp.results().empty())
  {
    return true;
  }
  return !resp.results()[0].is_good();
}

}  // namespace

// Part 18 section 4.4: the RoleType Properties and Methods "shall only be browseable, readable,
// writeable and callable by authorized administrators through an encrypted channel". Four operations,
// and browse is the one that is usually left open - Read, Write and Call each have an obvious place to
// hang a check, whereas Browse is a discovery service nobody thinks of as disclosing anything. It
// discloses the whole Role structure: which identities map to which Role, and therefore which
// credential is worth acquiring. This is the no-administrator-rights half of the clause; the caller
// here is Anonymous on a fully encrypted channel, so only the rights gate can refuse.
// @verifies AC-SVR-SECADMIN-025-ROLETYPE-ADMIN-ENCRYPTED
TEST_F(RbacManagementNonAdminFixture, RoleTypeMembersAreRefusedToNonAdministrators)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RoleTypeNonAdmin");

  // Non-vacuity: both members really are on this server (server-side view, no authorization applied),
  // so an absent browse reference or a Bad read below is the gate and not a member that was never wired.
  auto addressSpace = mServer->address_space();
  ASSERT_TRUE(addressSpace.try_find_node_sync(NodeId{0, operatorIdentitiesProperty}))
    << "the Operator Identities Property must exist for its refusal to mean anything";
  ASSERT_TRUE(addressSpace.try_find_node_sync(NodeId{0, operatorAddIdentityMethod}))
    << "the Operator AddIdentity Method must exist for its refusal to mean anything";

  EXPECT_FALSE(browse_exposes_child(session, NodeId{0, operatorRoleId}, "Identities"))
    << "a non-administrator must not see the Identities Property when browsing a Role Object (Part 18 "
       "section 4.4) - the browse discloses the identity-to-Role mapping to a caller who may not read it";
  EXPECT_FALSE(browse_exposes_child(session, NodeId{0, operatorRoleId}, "AddIdentity"))
    << "a non-administrator must not see the AddIdentity Method when browsing a Role Object (Part 18 "
       "section 4.4)";

  EXPECT_TRUE(read_value_refused(session, NodeId{0, operatorIdentitiesProperty}))
    << "a non-administrator must not be able to read the Identities Property";
  EXPECT_TRUE(direct_write_refused(session, NodeId{0, operatorIdentitiesProperty}))
    << "a non-administrator must not be able to write the Identities Property";

  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("mallory")}}),
    Status::BadUserAccessDenied)
    << "a non-administrator must not be able to call a RoleType Method";

  // A refusal that mutated the Role first would report Bad and still have granted the mapping.
  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, "mallory"), 0u)
    << "the refused RoleType operations must not have altered the Role's identity mapping";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.4, the other condition of the same clause: administrator rights are necessary and
// not sufficient - the channel must also be encrypted. This is the half a server passes when it checks
// only who the caller is, which is the natural implementation because the rights check is per-Node and
// already written; the channel is a property of the connection and nothing in the Read or Browse path
// looks at it. The caller here holds SecurityAdmin throughout, so only the channel gate can refuse, and
// the encrypted control that opens the test is what makes each refusal attributable to the channel
// rather than to a server that refuses these members to everybody.
// @verifies AC-SVR-SECADMIN-025-ROLETYPE-ADMIN-ENCRYPTED
TEST_F(RbacManagementAdminFixture, RoleTypeMembersAreRefusedToAdminsOnUnencryptedChannels)
{
  {
    // Control: the same administrator over SignAndEncrypt browses, reads and calls the same members.
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "RoleTypeAdminEnc");
    EXPECT_TRUE(browse_exposes_child(session, NodeId{0, operatorRoleId}, "Identities"))
      << "an administrator on an encrypted channel must see the Identities Property - without this the "
         "browse refusals below would prove nothing";
    EXPECT_TRUE(browse_exposes_child(session, NodeId{0, operatorRoleId}, "AddIdentity"))
      << "an administrator on an encrypted channel must see the AddIdentity Method";
    EXPECT_FALSE(read_value_refused(session, NodeId{0, operatorIdentitiesProperty}))
      << "an administrator on an encrypted channel must be able to read the Identities Property";
    EXPECT_EQ(call_status(session,
                NodeId{0, operatorRoleId},
                NodeId{0, operatorAddIdentityMethod},
                {Variant{username_rule("alice")}}),
      Status::Good)
      << "an administrator on an encrypted channel must be able to call a RoleType Method";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  {
    // The obligation: the same administrator, the same members, an unencrypted (Sign) channel.
    auto [channel, session] = open_session(MessageSecurityMode::Sign, "RoleTypeAdminSign");
    EXPECT_FALSE(browse_exposes_child(session, NodeId{0, operatorRoleId}, "Identities"))
      << "administrator rights do not excuse the encrypted-channel condition: the Identities Property "
         "must not be browseable over an unencrypted channel (Part 18 section 4.4)";
    EXPECT_FALSE(browse_exposes_child(session, NodeId{0, operatorRoleId}, "AddIdentity"))
      << "nor may the AddIdentity Method be browseable over an unencrypted channel";
    EXPECT_TRUE(read_value_refused(session, NodeId{0, operatorIdentitiesProperty}))
      << "the Identities Property must not be readable over an unencrypted channel";
    EXPECT_TRUE(direct_write_refused(session, NodeId{0, operatorIdentitiesProperty}))
      << "the Identities Property must not be writeable over an unencrypted channel";
    EXPECT_EQ(call_status(session,
                NodeId{0, operatorRoleId},
                NodeId{0, operatorAddIdentityMethod},
                {Variant{username_rule("mallory")}}),
      Status::BadSecurityModeInsufficient)
      << "a RoleType Method must not be callable over an unencrypted channel";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  // The unencrypted attempts must have changed nothing, while the encrypted control did.
  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, "mallory"), 0u)
    << "the refused unencrypted RoleType operations must not have altered the Role's identity mapping";
  EXPECT_EQ(count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, "alice"), 1u)
    << "the permitted encrypted Call must have altered it - this is what makes the count above a "
       "measurement rather than a Role nothing can reach";
}

namespace
{

// The ApplicationUri the fixture's Client presents. `ComplianceRoleBasedSecurity` aligns the client's
// ApplicationConfig with its certificate SAN at this value, and it is what the Applications
// predicate compares against.
constexpr const char* conjunctionClientApplicationUri = "urn:test:compliance:client";
constexpr const char* conjunctionAdminUser = "conjunction-admin";

/// A SecurityAdmin Role definition whose three Part 18 section 4.4 predicates are set independently, so
/// a test can fail exactly one of them and leave the other two satisfied.
///
/// The endpoint predicate is expressed as a SecurityMode filter rather than a URL filter: Part 18
/// section 4.4.2 makes every non-default field of an `EndpointType` entry narrow the match, and the
/// SecurityMode of the channel a Session was opened on is known to the test without depending on the
/// exact endpoint-URL string the server advertises.
RoleConfiguration::RoleDefinition security_admin_with_predicates(
  const std::string& userName, const std::string& applicationUri, MessageSecurityMode endpointSecurityMode)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)};
  def.roleBit = 7;
  def.identities.push_back(username_rule(userName));
  def.applications.push_back(String{applicationUri});
  def.applicationsExclude = false;
  EndpointType endpointFilter;
  endpointFilter.security_mode() = endpointSecurityMode;
  def.endpoints.push_back(std::move(endpointFilter));
  def.endpointsExclude = false;
  return def;
}

}  // namespace

/// SecurityAdmin configured with all three Part 18 section 4.4 predicates active and, as the fixture
/// leaves it, all three satisfied by the connecting Session. Each test phase rewrites the definition so
/// that exactly one predicate fails.
class RbacRoleGrantConjunctionFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    ASSERT_TRUE(config.add_role(security_admin_with_predicates(
      conjunctionAdminUser, conjunctionClientApplicationUri, MessageSecurityMode::SignAndEncrypt)))
      << "SecurityAdmin slot must register";
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, conjunctionAdminUser, std::unordered_map<std::string, std::string>{});
  }
};

// Part 18 section 4.4: "The Role shall only be granted to the Session if all of the following
// conditions are true" - the identity rules match, the Client's ApplicationUri satisfies the
// Applications filter, and the Endpoint the Session was opened through satisfies the Endpoints filter.
// The plausible implementation evaluates them as a disjunction, or evaluates only the one it
// implemented first and treats the others as advisory, and a test that checks only the all-true case
// cannot tell the difference: every such implementation grants the Role there too. So each predicate is
// failed alone, with the other two left satisfied.
//
// The grant is observed through its consequence rather than asserted on internal state: AddRole is
// admin-gated on the SecurityAdmin bit resolved at ActivateSession, so a Session that is refused it did
// not receive the Role. Each phase rewrites the live RoleConfiguration-the state AccessIdentity
// construction actually consults-and opens a fresh Session, which is where the mapping is evaluated.
// @verifies AC-SVR-SECADMIN-027-ROLE-GRANT-CONJUNCTION
TEST_F(RbacRoleGrantConjunctionFixture, RoleGrantedOnlyWhenAllThreePredicatesHold)
{
  // Control: all three hold, the Role is granted, and the admin-gated Method really does run for a
  // Session that holds it. Without this every refusal below would be satisfied by a server that grants
  // the Role to nobody.
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "GrantAllThree");
    const NodeId controlRoleId = add_role(session, "ConjunctionControlRole", namespace_uri_for_index(1));
    ASSERT_FALSE(controlRoleId.is_null())
      << "with all three predicates satisfied the Session must hold SecurityAdmin and AddRole must run";
    EXPECT_TRUE(roleConfiguration->get_role(controlRoleId)) << "the control AddRole must have registered "
                                                               "the Role it reported";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  // (1) Identity fails alone: the rule names a different user, the Applications and Endpoints filters
  // still admit this Session.
  ASSERT_TRUE(roleConfiguration->add_role(security_admin_with_predicates(
    "somebody-else", conjunctionClientApplicationUri, MessageSecurityMode::SignAndEncrypt)));
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "GrantIdentityFails");
    EXPECT_EQ(call_status(session,
                NodeId{0, roleSetId},
                NodeId{0, addRoleMethodId},
                {Variant{String{"ConjunctionIdentityRole"}}, Variant{namespace_uri_for_index(1)}}),
      Status::BadUserAccessDenied)
      << "a Session whose identity matches no IdentityMappingRule must not be granted the Role, however "
         "well it satisfies the Applications and Endpoints filters";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  // (2) Applications fails alone: the include list names an ApplicationUri this Client does not present.
  ASSERT_TRUE(roleConfiguration->add_role(security_admin_with_predicates(
    conjunctionAdminUser, "urn:test:some-other-client", MessageSecurityMode::SignAndEncrypt)));
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "GrantApplicationFails");
    EXPECT_EQ(call_status(session,
                NodeId{0, roleSetId},
                NodeId{0, addRoleMethodId},
                {Variant{String{"ConjunctionApplicationRole"}}, Variant{namespace_uri_for_index(1)}}),
      Status::BadUserAccessDenied)
      << "a Session whose Client ApplicationUri is outside the Applications include list must not be "
         "granted the Role, however well it satisfies the identity rules and the Endpoints filter";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  // (3) Endpoints fails alone: the include list admits only a None-mode Endpoint, and the Session is
  // opened on a SignAndEncrypt one.
  ASSERT_TRUE(roleConfiguration->add_role(security_admin_with_predicates(
    conjunctionAdminUser, conjunctionClientApplicationUri, MessageSecurityMode::None)));
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "GrantEndpointFails");
    EXPECT_EQ(call_status(session,
                NodeId{0, roleSetId},
                NodeId{0, addRoleMethodId},
                {Variant{String{"ConjunctionEndpointRole"}}, Variant{namespace_uri_for_index(1)}}),
      Status::BadUserAccessDenied)
      << "a Session opened through an Endpoint outside the Endpoints include list must not be granted "
         "the Role, however well it satisfies the identity rules and the Applications filter";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  // And none of the three refused calls did the work anyway. AddRole enforces BrowseName uniqueness
  // within the RoleSet Object (Part 18 section 4.2.2), so with the all-pass configuration restored a
  // name that is still free is a name no refused call consumed; a refusal that had created the Role
  // regardless would collide here with Bad_InvalidArgument.
  ASSERT_TRUE(roleConfiguration->add_role(security_admin_with_predicates(
    conjunctionAdminUser, conjunctionClientApplicationUri, MessageSecurityMode::SignAndEncrypt)));
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "GrantRestored");
    for (const char* refusedName :
      {"ConjunctionIdentityRole", "ConjunctionApplicationRole", "ConjunctionEndpointRole"})
    {
      EXPECT_EQ(call_status(session,
                  NodeId{0, roleSetId},
                  NodeId{0, addRoleMethodId},
                  {Variant{String{std::string{refusedName}}}, Variant{namespace_uri_for_index(1)}}),
        Status::Good)
        << "the refused AddRole must not have created " << refusedName
        << " - the name is taken, so a Session that was denied the Role did the work anyway";
    }
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }
}

// Part 18 section 4.2.3 permits a finite propagation delay after Role mappings change, not a grant that
// remains valid for the lifetime of an already activated Session. This keeps one Session and one secured
// channel throughout all three phases so opening or reactivating a Session cannot refresh the result for
// the implementation under test.
// @relation(AC-SVR-SECADMIN-027-ACTIVE-SESSION-ROLE-REFRESH, scope=function)
TEST_F(RbacRoleGrantConjunctionFixture, ActiveSessionLosesAndRegainsRoleAfterIdentityMappingChange)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ActiveRoleRefresh");

  EXPECT_EQ(call_status(session,
              NodeId{0, roleSetId},
              NodeId{0, addRoleMethodId},
              {Variant{String{"ActiveRoleRefreshControl"}}, Variant{namespace_uri_for_index(1)}}),
    Status::Good)
    << "the established Session must initially hold SecurityAdmin, or the revocation phase is vacuous";

  ASSERT_TRUE(roleConfiguration->add_role(security_admin_with_predicates(
    "somebody-else", conjunctionClientApplicationUri, MessageSecurityMode::SignAndEncrypt)));
  EXPECT_EQ(call_status(session,
              NodeId{0, roleSetId},
              NodeId{0, addRoleMethodId},
              {Variant{String{"ActiveRoleRefreshDenied"}}, Variant{namespace_uri_for_index(1)}}),
    Status::BadUserAccessDenied)
    << "removing the Session's identity mapping must revoke the Role on its next protected operation";

  ASSERT_TRUE(roleConfiguration->add_role(security_admin_with_predicates(
    conjunctionAdminUser, conjunctionClientApplicationUri, MessageSecurityMode::SignAndEncrypt)));
  EXPECT_EQ(call_status(session,
              NodeId{0, roleSetId},
              NodeId{0, addRoleMethodId},
              {Variant{String{"ActiveRoleRefreshRestored"}}, Variant{namespace_uri_for_index(1)}}),
    Status::Good)
    << "restoring the mapping must restore the Role without replacing or reactivating the Session";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// Round-9: the two include/exclude filter polarities (SVR-SECADMIN-028 / -030),
// the well-known Role authority split (SVR-SECADMIN-063 / -067 / -068) and the
// TrustedApplication Role (SVR-SECADMIN-069).
// ============================================================================

namespace
{

// The ApplicationUri this fixture chain's Client presents. `ComplianceRoleBasedSecurity`
// aligns the client's ApplicationConfig with its certificate SAN at this value, and it
// is what the Applications predicate compares a Session against.
constexpr const char* filterClientApplicationUri = "urn:test:compliance:client";
constexpr const char* filterOtherApplicationUri = "urn:test:some-other-client";
constexpr const char* filterAdminUser = "filter-admin";

constexpr uint32_t securityAdminRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin);
constexpr uint32_t configureAdminRoleId = static_cast<uint32_t>(ObjectId::WellKnownRole_ConfigureAdmin);
constexpr uint32_t trustedApplicationRoleId =
  static_cast<uint32_t>(ObjectId::WellKnownRole_TrustedApplication);

/// A well-known Role definition granted to `userName` by a UserName identity rule. Pre-registering
/// the slot makes `seed_well_known_roles` leave it alone and keep the rule; the Role's *Permissions*
/// still come from the server, which is what keeps the tests below off their own configuration.
RoleConfiguration::RoleDefinition well_known_role_for_user(
  ObjectId role, uint8_t roleBit, const std::string& userName)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = NodeId{0, static_cast<uint32_t>(role)};
  def.roleBit = roleBit;
  def.identities.push_back(username_rule(userName));
  return def;
}

/// SecurityAdmin granted to `userName`, filtered by an `Applications` list naming exactly
/// `applicationUri`. `exclude` engaged assigns `ApplicationsExclude`; `exclude` disengaged leaves
/// the field at what a default-constructed `RoleDefinition` carries - the "Property is not
/// provided" arm of Part 18 section 4.4, which is the arm the test cannot fake by assigning FALSE.
RoleConfiguration::RoleDefinition security_admin_with_applications(
  const std::string& userName, const std::string& applicationUri, std::optional<bool> exclude)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = NodeId{0, securityAdminRoleId};
  def.roleBit = 7;
  def.identities.push_back(username_rule(userName));
  def.applications.push_back(String{applicationUri});
  if (exclude.has_value())
  {
    def.applicationsExclude = *exclude;
  }
  return def;
}

/// SecurityAdmin granted to `userName`, filtered by an `Endpoints` list naming exactly one
/// EndpointType entry whose only non-default field is its SecurityMode. Part 18 section 4.4.2
/// makes every non-default field narrow the match, so a single-field entry is the cleanest
/// endpoint predicate a test can state; the SecurityMode of the channel a Session was opened on is
/// known here without depending on the exact endpoint-URL string the server advertises.
/// `exclude` disengaged leaves `EndpointsExclude` unassigned - the "not provided" arm.
RoleConfiguration::RoleDefinition security_admin_with_endpoints(
  const std::string& userName, MessageSecurityMode endpointSecurityMode, std::optional<bool> exclude)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = NodeId{0, securityAdminRoleId};
  def.roleBit = 7;
  def.identities.push_back(username_rule(userName));
  EndpointType entry;
  entry.security_mode() = endpointSecurityMode;
  def.endpoints.push_back(std::move(entry));
  if (exclude.has_value())
  {
    def.endpointsExclude = *exclude;
  }
  return def;
}

}  // namespace

/// SecurityAdmin reached through an `Applications` filter. The fixture installs the include-list
/// arm; each phase of the test rewrites the definition so that only the filter differs.
class RbacApplicationsExcludeFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    ASSERT_TRUE(config.add_role(
      security_admin_with_applications(filterAdminUser, filterClientApplicationUri, std::nullopt)))
      << "SecurityAdmin slot must register";
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, filterAdminUser, std::unordered_map<std::string, std::string>{});
  }
};

/// The endpoint twin of the fixture above.
class RbacEndpointsExcludeFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    ASSERT_TRUE(config.add_role(
      security_admin_with_endpoints(filterAdminUser, MessageSecurityMode::SignAndEncrypt, std::nullopt)))
      << "SecurityAdmin slot must register";
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, filterAdminUser, std::unordered_map<std::string, std::string>{});
  }
};

// Part 18 section 4.4: "If this Property is not provided or has a value of FALSE then only
// Applications included in the Applications Property shall be included." Absent and FALSE must
// behave identically, and that is the whole content of the clause. The plausible implementation
// gets it wrong at the default: `AddRole` is obliged to create Roles with `ApplicationsExclude`
// TRUE (section 4.2.2 L316-318), so a server that carries that same TRUE default into the Role
// definition an administrator authors - or that reads "flag not set" as "no restriction" -
// silently inverts every Role whose author did not think the flag mattered, turning an allow-list
// into a deny-list. A test that only ever sets the flag explicitly cannot see it.
//
// All six cells of the matrix are asserted, because each polarity has an "only" half that the
// matching half cannot prove: that the listed application is admitted says nothing about whether
// an unlisted one is admitted too, and a server that ignores the filter entirely passes any three
// of the six. The verdict is the admin-gated AddRole - the Session that is granted SecurityAdmin
// runs it, the Session that is not is refused - so the grant is observed through its consequence
// rather than read off internal state.
// @verifies AC-SVR-SECADMIN-028-APPLICATIONSEXCLUDE
// clang-format off
// The TEST_F line below must stay on ONE physical line.
TEST_F(RbacApplicationsExcludeFixture, ApplicationsListIncludesOnlyItsMembersUnlessApplicationsExcludeIsTrue)
// clang-format on
{
  // Each phase installs one Role definition on the live RoleConfiguration-the state AccessIdentity
  // construction consults-and then opens a FRESH Session, because the identity-to-Role mapping is
  // evaluated at ActivateSession. Every Session is opened on a SignAndEncrypt channel, which
  // satisfies the section 4.4.1 signed-channel floor an Applications-filtered Role additionally
  // requires, so the floor can never be what refuses one of these calls.
  auto verdict =
    [this](RoleConfiguration::RoleDefinition definition, const char* roleName, const std::string& sessionName)
  {
    EXPECT_TRUE(roleConfiguration->add_role(std::move(definition)))
      << "the Role definition under test must install";
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, sessionName);
    const StatusCode status = call_status(session,
      NodeId{0, roleSetId},
      NodeId{0, addRoleMethodId},
      {Variant{String{std::string{roleName}}}, Variant{namespace_uri_for_index(1)}});
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
    return status;
  };

  // Absent: the flag was never assigned. Whitelist - the listed application is in, everything else
  // is out.
  EXPECT_EQ(
    verdict(security_admin_with_applications(filterAdminUser, filterClientApplicationUri, std::nullopt),
      "AppsAbsentListed",
      "AppsAbsentListed"),
    Status::Good)
    << "with ApplicationsExclude not provided, the Client named in the Applications list must be "
       "granted the Role (Part 18 section 4.4)";
  EXPECT_EQ(
    verdict(security_admin_with_applications(filterAdminUser, filterOtherApplicationUri, std::nullopt),
      "AppsAbsentUnlisted",
      "AppsAbsentUnlisted"),
    Status::BadUserAccessDenied)
    << "and a Client absent from that list must NOT be granted it - an absent flag read as "
       "permissive turns the allow-list into a deny-list";

  // FALSE: explicitly stated, and it must behave exactly as absent did.
  EXPECT_EQ(verdict(security_admin_with_applications(filterAdminUser, filterClientApplicationUri, false),
              "AppsFalseListed",
              "AppsFalseListed"),
    Status::Good)
    << "ApplicationsExclude=FALSE must include the listed Client, identically to the absent case";
  EXPECT_EQ(verdict(security_admin_with_applications(filterAdminUser, filterOtherApplicationUri, false),
              "AppsFalseUnlisted",
              "AppsFalseUnlisted"),
    Status::BadUserAccessDenied)
    << "and exclude nothing else, identically to the absent case";

  // TRUE: the list inverts. The listed application is the one excluded; every other one is in.
  EXPECT_EQ(verdict(security_admin_with_applications(filterAdminUser, filterClientApplicationUri, true),
              "AppsTrueListed",
              "AppsTrueListed"),
    Status::BadUserAccessDenied)
    << "ApplicationsExclude=TRUE must EXCLUDE the Client named in the Applications list";
  EXPECT_EQ(verdict(security_admin_with_applications(filterAdminUser, filterOtherApplicationUri, true),
              "AppsTrueUnlisted",
              "AppsTrueUnlisted"),
    Status::Good)
    << "and include every application except it - a server that treats TRUE as 'deny everyone' "
       "would refuse here too";
}

// Part 18 section 4.4: "If this Property is not provided or has a value of FALSE then only
// Endpoints included in the Endpoints Property shall be included." The endpoints twin of
// `AC-SVR-SECADMIN-028-APPLICATIONSEXCLUDE`, with the same absent-equals-FALSE trap and a wider
// scope of change: the Endpoints filter decides WHERE a Role's permissions apply, so an inverted
// list grants a Role on precisely the endpoints an administrator meant to withhold it from.
// SVR-SECADMIN-030 additionally records that the Endpoint filter was a Phase 1 follow-up, so the
// unimplemented shape - the filter never consulted at all - passes any test that checks only the
// match case.
//
// All six cells are asserted. A filter that is ignored returns Good in all six; a filter stuck on
// exclude returns Good in exactly the three the include arms deny.
// @verifies AC-SVR-SECADMIN-030-ENDPOINTSEXCLUDE
// clang-format off
// The TEST_F line below must stay on ONE physical line.
TEST_F(RbacEndpointsExcludeFixture, EndpointsListIncludesOnlyItsMembersUnlessEndpointsExcludeIsTrue)
// clang-format on
{
  // Every Session below is opened on the SignAndEncrypt endpoint, so the SignAndEncrypt filter
  // entry is the "named endpoint" and the Sign entry is an endpoint this Session did not come
  // through. Both endpoints really exist on this server (`ComplianceSecured` installs None, Sign
  // and SignAndEncrypt), so neither filter names something unreachable.
  auto verdict =
    [this](RoleConfiguration::RoleDefinition definition, const char* roleName, const std::string& sessionName)
  {
    EXPECT_TRUE(roleConfiguration->add_role(std::move(definition)))
      << "the Role definition under test must install";
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, sessionName);
    const StatusCode status = call_status(session,
      NodeId{0, roleSetId},
      NodeId{0, addRoleMethodId},
      {Variant{String{std::string{roleName}}}, Variant{namespace_uri_for_index(1)}});
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
    return status;
  };

  // Absent: the flag was never assigned. Whitelist.
  EXPECT_EQ(
    verdict(security_admin_with_endpoints(filterAdminUser, MessageSecurityMode::SignAndEncrypt, std::nullopt),
      "EndpointsAbsentListed",
      "EndpointsAbsentListed"),
    Status::Good)
    << "with EndpointsExclude not provided, a Session opened through the Endpoint named in the "
       "Endpoints list must be granted the Role (Part 18 section 4.4)";
  EXPECT_EQ(verdict(security_admin_with_endpoints(filterAdminUser, MessageSecurityMode::Sign, std::nullopt),
              "EndpointsAbsentUnlisted",
              "EndpointsAbsentUnlisted"),
    Status::BadUserAccessDenied)
    << "and a Session opened through an Endpoint outside that list must NOT be granted it";

  // FALSE: explicitly stated, and it must behave exactly as absent did.
  EXPECT_EQ(
    verdict(security_admin_with_endpoints(filterAdminUser, MessageSecurityMode::SignAndEncrypt, false),
      "EndpointsFalseListed",
      "EndpointsFalseListed"),
    Status::Good)
    << "EndpointsExclude=FALSE must include the listed Endpoint, identically to the absent case";
  EXPECT_EQ(verdict(security_admin_with_endpoints(filterAdminUser, MessageSecurityMode::Sign, false),
              "EndpointsFalseUnlisted",
              "EndpointsFalseUnlisted"),
    Status::BadUserAccessDenied)
    << "and exclude every other Endpoint, identically to the absent case";

  // TRUE: the list inverts.
  EXPECT_EQ(verdict(security_admin_with_endpoints(filterAdminUser, MessageSecurityMode::SignAndEncrypt, true),
              "EndpointsTrueListed",
              "EndpointsTrueListed"),
    Status::BadUserAccessDenied)
    << "EndpointsExclude=TRUE must EXCLUDE the Endpoint named in the Endpoints list";
  EXPECT_EQ(verdict(security_admin_with_endpoints(filterAdminUser, MessageSecurityMode::Sign, true),
              "EndpointsTrueUnlisted",
              "EndpointsTrueUnlisted"),
    Status::Good)
    << "and include every Endpoint except it";
}

/// The server materialises all nine well-known Roles (the fixture leaves `wellKnownRoles` at its
/// default, which is the `Security Role TrustedApplication` CU declared), and one Variable is
/// gated on the well-known `TrustedApplication` Role alone - the permission assignment whose
/// usability the criterion asks about.
///
/// The Session is an administrator so that the RoleSet browse below cannot be confounded by the
/// Part 18 section 4.4 administrator filter on that surface; the TrustedApplication grant it is
/// really testing is orthogonal to that, being decided by the Role's own IdentityCriteria.
class RbacTrustedApplicationRoleFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTrustedApplicationGatedVariable;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_user(config, "admin");
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "admin", std::unordered_map<std::string, std::string>{});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:trusted-application-role");
    mTrustedApplicationGatedVariable = NodeId{nsIndex, uint32_t{74001}};
    create_role_gated_variable(addressSpace,
      mTrustedApplicationGatedVariable,
      "TrustedApplicationRoleGatedInt32",
      {make_role_permission(
        NodeId{0, trustedApplicationRoleId}, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

// Part 3 section 4.8.2 with Part 18 section 4.3 Table 3: on a Server declaring the
// `Security Role TrustedApplication` conformance unit the well-known `TrustedApplication` Role is
// materialised and usable. The Role is Optional, which is exactly what makes the obligation easy
// to leave half-done: a server that stops at "the enumeration value exists" ships a Role that
// never appears under the RoleSet, and a server that materialises the Object but never seeds its
// `TrustedApplication` IdentityCriteria (Part 18 section 4.4.3 - trusted certificate on an
// at-least-Signed channel, with no ApplicationUri comparison) ships a Role no Session can ever
// hold, so naming it in a permission assignment silently denies everyone.
//
// Both conjuncts are asserted, and the second is asserted through a real Read: a Node whose
// RolePermissions name TrustedApplication and nothing else is readable by a Session the server
// itself decided to grant the Role to. The None-channel arm is the control - no client certificate
// is presented at OPN there, so the criteria cannot match and the same Read must be refused;
// without it a server that grants every Role to every Session would pass.
// @verifies AC-SVR-SECADMIN-069-TRUSTEDAPPLICATION-ROLE
// clang-format off
// The TEST_F line below must stay on ONE physical line.
TEST_F(RbacTrustedApplicationRoleFixture, TrustedApplicationRoleIsInTheRoleSetAndUsableInPermissionAssignments)
// clang-format on
{
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "TrustedAppRolePresent");

    EXPECT_TRUE(browse_exposes_child(session, NodeId{0, roleSetId}, "TrustedApplication"))
      << "the well-known TrustedApplication Role Object must be present under the RoleSet on a "
         "server declaring the Security Role TrustedApplication CU (Part 18 section 4.3 Table 3)";

    auto readResp = session.attributes().read_sync(read_value(mTrustedApplicationGatedVariable));
    ASSERT_THAT(readResp, ServiceResultIsGood());
    ASSERT_FALSE(readResp.results().empty());
    EXPECT_THAT(readResp.results()[0], HasStatus(Status::Good))
      << "a Node whose RolePermissions name the well-known TrustedApplication Role and nothing else "
         "must be readable by a Session the server granted that Role - a Role that cannot be granted "
         "is not usable in permission assignments";

    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  {
    // Control. A None-mode channel presents no client certificate, so the TrustedApplication
    // criteria cannot match and the Role is not granted. The SAME Read must now be refused - and
    // this Session still authenticates as the administrator, so the refusal is the absence of
    // TrustedApplication and nothing else about the caller.
    auto [channel, session] = open_session(MessageSecurityMode::None, "TrustedAppRoleNone");

    auto readResp = session.attributes().read_sync(read_value(mTrustedApplicationGatedVariable));
    ASSERT_THAT(readResp, ServiceResultIsGood());
    ASSERT_FALSE(readResp.results().empty());
    EXPECT_THAT(readResp.results()[0], HasStatus(Status::BadUserAccessDenied))
      << "a Session that cannot satisfy the TrustedApplication criteria must be refused the same "
         "Read - this is what makes the grant above attributable to the Role";

    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }
}

namespace
{

constexpr const char* securityAdminUser = "security-admin-user";
constexpr const char* securityAdminAddedIdentity = "added-by-security-admin";
constexpr const char* nonSecurityAdminAddedIdentity = "added-without-security-admin";

}  // namespace

/// One user holding BOTH SecurityAdmin and ConfigureAdmin. The test's second phase rewrites the
/// SecurityAdmin definition so that it names somebody else, which leaves the very same caller
/// holding ConfigureAdmin alone - an administrator in every other respect, and the sharpest
/// available reading of "a Session without the Role".
class RbacSecurityAdminAuthorityFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    ASSERT_TRUE(
      config.add_role(well_known_role_for_user(ObjectId::WellKnownRole_SecurityAdmin, 7, securityAdminUser)))
      << "SecurityAdmin slot must register";
    ASSERT_TRUE(
      config.add_role(well_known_role_for_user(ObjectId::WellKnownRole_ConfigureAdmin, 6, securityAdminUser)))
      << "ConfigureAdmin slot must register";
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, securityAdminUser, std::unordered_map<std::string, std::string>{});
  }
};

// Part 18 section 4.3 with Part 3 section 4.8.2 Table 2: "The Role is allowed to change security
// related settings" - and, as the counterpart of ConfigureAdmin in the separation of duties, it is
// the only well-known Role that is. The security-related setting exercised here is the
// identity-to-Role mapping itself (the Part 18 section 4.4 RoleType surface), which is the setting
// whose misassignment hands out every other one.
//
// The plausible implementation collapses the two administrative Roles into one "admin" notion,
// because a single administrative Role is simpler to configure and every management Method already
// has an admin gate to hang the check on. That server passes the first half of this test and fails
// the second: the caller below holds ConfigureAdmin throughout, so a merged notion would let the
// second phase through. Both phases run against the same server as the same user over the same
// channel mode, with only the SecurityAdmin grant differing, and the refusal is checked to have
// changed nothing - a server that mutates before it authorises has already granted the mapping.
// @verifies AC-SVR-SECADMIN-068-SECURITYADMIN-PERMISSIONS
// clang-format off
// The TEST_F line below must stay on ONE physical line.
TEST_F(RbacSecurityAdminAuthorityFixture, OnlyASessionHoldingSecurityAdminMayChangeASecurityRelatedSetting)
// clang-format on
{
  {
    // The Role IS held: the security-related change succeeds and lands.
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "SecurityAdminChanges");
    EXPECT_EQ(call_status(session,
                NodeId{0, operatorRoleId},
                NodeId{0, operatorAddIdentityMethod},
                {Variant{username_rule(std::string{securityAdminAddedIdentity})}}),
      Status::Good)
      << "a SecurityAdmin Session must be able to change a security-related setting (Part 18 "
         "section 4.3)";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }
  EXPECT_EQ(
    count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, securityAdminAddedIdentity), 1u)
    << "and the change must actually have been applied - a Good that changed nothing is not a change";

  // Take SecurityAdmin away from this user and leave ConfigureAdmin in place. Nothing else about
  // the caller, the server or the call changes.
  ASSERT_TRUE(roleConfiguration->add_role(
    well_known_role_for_user(ObjectId::WellKnownRole_SecurityAdmin, 7, "somebody-else-entirely")))
    << "the SecurityAdmin definition must be replaceable";
  ASSERT_EQ(count_username_rules(*roleConfiguration, NodeId{0, securityAdminRoleId}, securityAdminUser), 0u)
    << "the caller must no longer be named by the SecurityAdmin Role";
  ASSERT_EQ(count_username_rules(*roleConfiguration, NodeId{0, configureAdminRoleId}, securityAdminUser), 1u)
    << "and must still be named by ConfigureAdmin - the Session is still an administrator, just not "
       "a security administrator";

  {
    // The Role is NOT held: the identical change is refused.
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "NoSecurityAdminChanges");
    EXPECT_EQ(call_status(session,
                NodeId{0, operatorRoleId},
                NodeId{0, operatorAddIdentityMethod},
                {Variant{username_rule(std::string{nonSecurityAdminAddedIdentity})}}),
      Status::BadUserAccessDenied)
      << "a Session without SecurityAdmin must be refused the same security-related change, however "
         "administrative it is otherwise";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }

  auto def = roleConfiguration->get_role(NodeId{0, operatorRoleId});
  ASSERT_TRUE(def);
  ASSERT_FALSE(def->identities.empty()) << "the refused change emptied the Role's identity mapping";
  EXPECT_EQ(
    count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, nonSecurityAdminAddedIdentity), 0u)
    << "the refused change must not have been applied anyway";
  EXPECT_EQ(
    count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, securityAdminAddedIdentity), 1u)
    << "and must have left the permitted change in place";
}

// ============================================================================
// The well-known Role default-Permission surface (SVR-SECADMIN-063 / -067).
//
// Both obligations are about the Permissions the SERVER publishes for a Role, so nothing below may
// stamp a per-Node `RolePermissions` override: `create_role_gated_variable` always does, which
// would make the test assert its own configuration. The namespace here therefore carries the
// server's own published defaults - read back out of the NS0 `DefaultRolePermissions` Property the
// server populated at startup - and every Node in it is created bare, so each decision falls
// through to those defaults.
// ============================================================================

namespace
{

constexpr uint32_t defaultRolePermissionsPropertyId =
  static_cast<uint32_t>(VariableId::OPCUANamespaceMetadata_DefaultRolePermissions);

/// Window covering every pre-loaded history value with margin.
const DateTime surfaceHistoryStart{2020, 1, 1, 0, 0, 0.0};
const DateTime surfaceHistoryEnd{2030, 1, 1, 0, 0, 0.0};

/// Minimal raw-history store so a history Read that a Role *permits* can return data. Without it
/// every history Read ends in `Bad_HistoryOperationUnsupported` and the Role gate is unobservable
/// in either direction.
class RoleSurfaceHistoryDelegate : public NamespaceHistoryDelegate
{
public:
  void add_values(const NodeId& nodeId, std::vector<DataValue> values)
  {
    std::lock_guard lock(mMutex);
    auto& existing = mData[nodeId];
    existing.insert(
      existing.end(), std::make_move_iterator(values.begin()), std::make_move_iterator(values.end()));
  }

  Capabilities capabilities() const noexcept override
  {
    Capabilities caps;
    caps.readRaw = true;
    return caps;
  }

  void read_raw_async(const NamespaceHistoryDelegate::ReadContext& /*context*/,
    std::vector<NamespaceHistoryDelegate::ReadRawItem> items, ReadRawCallback callback) noexcept override
  {
    BatchResult<NamespaceHistoryDelegate::ReadRawItemResult> batch;
    batch.items.reserve(items.size());

    std::lock_guard lock(mMutex);
    for (const auto& item : items)
    {
      NamespaceHistoryDelegate::HistoryReadRawSuccess success;
      auto it = mData.find(item.nodeId);
      if (it != mData.end())
      {
        for (const auto& dv : it->second)
        {
          success.values.push_back(dv);
        }
      }
      batch.items.emplace_back(std::move(success));
    }

    callback(std::move(batch));
  }

private:
  std::mutex mMutex;
  std::unordered_map<NodeId, std::vector<DataValue>> mData;
};

/// Namespace that carries the server's own well-known-Role defaults as its
/// `DefaultRolePermissions` and serves raw history from the delegate above.
class RoleSurfaceNamespace : public default_ns::Namespace
{
public:
  using default_ns::Namespace::Namespace;

  static std::shared_ptr<RoleSurfaceNamespace> create(String uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<RoleSurfaceNamespace>(
      new RoleSurfaceNamespace(std::move(uri), std::move(executor)));
  }

  void set_delegate(std::shared_ptr<RoleSurfaceHistoryDelegate> delegate)
  {
    mDelegate = std::move(delegate);
  }

  std::shared_ptr<NamespaceHistoryDelegate> history_delegate() noexcept override
  {
    return mDelegate;
  }

private:
  std::shared_ptr<RoleSurfaceHistoryDelegate> mDelegate;
};

/// The server's own well-known-Role default Permissions, read from the canonical namespace interface
/// that also answers the wire-visible `DefaultRolePermissions` Property. Sourcing the array from
/// production state stops the Role tests below from asserting against Permissions the test invented
/// without depending on the Property's inert stored placeholder.
std::vector<RolePermissionType> published_role_defaults(AddressSpace& addressSpace)
{
  const auto nameSpace = addressSpace.namespace_array().get_namespace(0);
  if (!nameSpace)
  {
    ADD_FAILURE() << "NS0 namespace is unavailable";
    return {};
  }
  const auto defaults = nameSpace->default_role_permissions();
  if (!defaults)
  {
    ADD_FAILURE() << "NS0 does not expose the standard Role Permission model";
    return {};
  }
  return *defaults;
}

/// Create a Subscription and one data MonitoredItem on `nodeId`, returning the per-item status.
/// `CreateMonitoredItems` is where Part 4 section 5.12.2.1 gates a data subscription
/// (`AccessOperation::Read`), so this is the observable for "subscribe". The Subscription is
/// deleted again once that status has been captured, so no sampling registration is left armed at
/// teardown.
StatusCode subscribe_to_data_value(Session& session, const NodeId& nodeId)
{
  CreateSubscriptionRequest subReq;
  subReq.requested_publishing_interval() = 100.0;
  subReq.requested_lifetime_count() = 100;
  subReq.requested_max_keep_alive_count() = 10;
  subReq.max_notifications_per_publish() = 0;
  subReq.publishing_enabled() = true;
  subReq.priority() = 0;
  auto subResp = session.subscriptions().create_subscription_sync(std::move(subReq));
  if (!subResp.response_header().service_result().is_good())
  {
    return subResp.response_header().service_result();
  }

  ReadValueId monitored;
  monitored.node_id() = nodeId;
  monitored.attribute_id() = static_cast<uint32_t>(AttributeId::Value);

  MonitoringParameters params;
  params.client_handle() = 1;
  params.sampling_interval() = 100.0;
  params.queue_size() = 1;
  params.discard_oldest() = true;

  MonitoredItemCreateRequest item;
  item.item_to_monitor() = std::move(monitored);
  item.monitoring_mode() = MonitoringMode::Reporting;
  item.requested_parameters() = std::move(params);

  CreateMonitoredItemsRequest req;
  req.subscription_id() = subResp.subscription_id();
  req.timestamps_to_return() = TimestampsToReturn::Both;
  req.items_to_create().push_back(std::move(item));

  auto resp = session.monitored_items().create_monitored_items_sync(std::move(req));

  DeleteSubscriptionsRequest delReq;
  delReq.subscription_ids().push_back(subResp.subscription_id());
  (void)session.subscriptions().try_delete_subscriptions_sync(std::move(delReq));

  if (!resp.response_header().service_result().is_good())
  {
    return resp.response_header().service_result();
  }
  if (resp.results().empty())
  {
    ADD_FAILURE() << "CreateMonitoredItems returned no per-item result";
    return StatusCode{Status::BadInternalError};
  }
  return resp.results()[0].status_code();
}

}  // namespace

/// One Object (the Browse target), one Variable carrying live data plus raw history and an open
/// DisplayName WriteMask (the configuration-data surface), and one Method with a handler installed
/// - none of them carrying a per-Node `RolePermissions` override, so every decision falls through
/// to the namespace defaults, which are the server's own published Role defaults.
class WellKnownRoleSurfaceBase : public ComplianceRoleBasedSecurity
{
protected:
  void customize_address_space(AddressSpace& addressSpace) override
  {
    mHistory = std::make_shared<RoleSurfaceHistoryDelegate>();
    mTestNamespace =
      RoleSurfaceNamespace::create(String{"urn:test:wellknown-role-surface"}, mServerThreadPool.executor());
    mTestNamespace->set_delegate(mHistory);
    mTestNamespace->set_namespace_defaults(published_role_defaults(addressSpace), std::nullopt);
    mTestNsIndex = addressSpace.add_namespace_sync(mTestNamespace);

    mFolderId = NodeId{mTestNsIndex, uint32_t{74100}};
    mVariableId = NodeId{mTestNsIndex, uint32_t{74101}};
    mMethodId = NodeId{mTestNsIndex, uint32_t{74102}};

    auto folderNode = addressSpace.create_node_sync(mFolderId, NodeClass::Object);
    folderNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    auto folder = folderNode.as<ObjectAccessor>();
    ASSERT_TRUE(folder.has_value());
    folder->set_browse_name(QualifiedName{mTestNsIndex, "RoleSurfaceFolder"});
    folder->set_display_name(LocalizedText{"", "RoleSurfaceFolder"});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mFolderId);

    auto varNode = addressSpace.create_node_sync(mVariableId, NodeClass::Variable);
    auto variable = varNode.as<VariableAccessor>();
    ASSERT_TRUE(variable.has_value());
    variable->set_browse_name(QualifiedName{mTestNsIndex, "RoleSurfaceLiveData"});
    variable->set_display_name(LocalizedText{"", "RoleSurfaceLiveData"});
    variable->set_data_type(NodeId{DataTypeId::Int32});
    variable->write_value_sync(int32_t{7});
    // HistoryRead is the capability advertisement the HistoryRead service tests before it reaches
    // the Role gate; without it a refusal would be "unsupported", not "denied".
    variable->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead,
      AccessLevelType::Bit::CurrentWrite,
      AccessLevelType::Bit::HistoryRead});
    // Same reasoning for the configuration-data write: open the DisplayName WriteMask bit
    // statically so a refusal is the Role's, not a zero WriteMask.
    varNode.set_write_mask(AttributeWriteMask{AttributeWriteMask::Bit::DisplayName});
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mVariableId);

    auto methodNode = addressSpace.create_node_sync(mMethodId, NodeClass::Method);
    auto method = methodNode.as<MethodAccessor>();
    ASSERT_TRUE(method.has_value());
    method->set_browse_name(QualifiedName{mTestNsIndex, "RoleSurfaceMethod"});
    method->set_display_name(LocalizedText{"", "RoleSurfaceMethod"});
    method->set_executable(true);
    folderNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, mMethodId);
    {
      // A handler is installed so that a refused Call is attributable to the Role and not to a
      // missing implementation.
      auto* callSource = mTestNamespace->find_node<Node>(mMethodId)->method_call_source();
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

    std::vector<DataValue> history;
    for (int32_t i = 0; i < 3; ++i)
    {
      DataValue dv;
      dv.value() = Variant{int32_t{i}};
      dv.source_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.server_timestamp() = UtcTime{2025, 1, 1, 0, 0, static_cast<double>(i)};
      dv.status() = Status::Good;
      history.push_back(std::move(dv));
    }
    mHistory->add_values(mVariableId, std::move(history));
  }

  /// The namespace owns a `SamplingEngine` with periodic bucket timers, and a fixture member keeps
  /// it alive past the base teardown that joins the server thread pool. Drop the fixture's
  /// reference first so the address space holds the last one.
  void TearDown() override
  {
    mTestNamespace.reset();
    mHistory.reset();
    ComplianceRoleBasedSecurity::TearDown();
  }

  std::shared_ptr<RoleSurfaceNamespace> mTestNamespace;
  std::shared_ptr<RoleSurfaceHistoryDelegate> mHistory;
  uint16_t mTestNsIndex{0};
  NodeId mFolderId;
  NodeId mVariableId;
  NodeId mMethodId;
};

/// Observer Session: UserName "surface-observer" mapped onto the well-known Observer Role
/// (canonical bit 2). The Role's Permissions still come from the server.
class ObserverRoleSurfaceFixture : public WellKnownRoleSurfaceBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    ASSERT_TRUE(
      config.add_role(well_known_role_for_user(ObjectId::WellKnownRole_Observer, 2, "surface-observer")))
      << "Observer slot must register";
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "surface-observer", std::unordered_map<std::string, std::string>{});
  }
};

/// ConfigureAdmin Session: UserName "surface-configure-admin" mapped onto the well-known
/// ConfigureAdmin Role (canonical bit 6). SecurityAdmin is deliberately NOT granted.
class ConfigureAdminRoleSurfaceFixture : public WellKnownRoleSurfaceBase
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    ASSERT_TRUE(config.add_role(
      well_known_role_for_user(ObjectId::WellKnownRole_ConfigureAdmin, 6, "surface-configure-admin")))
      << "ConfigureAdmin slot must register";
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "surface-configure-admin", std::unordered_map<std::string, std::string>{});
  }
};

// Part 18 section 4.3 with Part 3 section 4.8.2 Table 2: Observer "is allowed to browse, read live
// data, read historical data/events or subscribe to data/events" - and nothing else. Observer is
// the first Role to carry history and subscription access, so the boundary that matters is the one
// it does not cross: no Write and no Method call. The plausible implementation folds Observer in
// with Operator, which differs from it by exactly those two operations, and hands a read-only
// account the ability to actuate; a test that checks only the four reads cannot see it.
//
// All six operations are asserted from the SAME Session, so neither a Role denied everything nor a
// Role granted everything can pass.
// @verifies AC-SVR-SECADMIN-063-OBSERVER-PERMISSIONS
// clang-format off
// The TEST_F line below must stay on ONE physical line.
TEST_F(ObserverRoleSurfaceFixture, ObserverRoleGrantsBrowseReadHistoryAndSubscribeButRefusesWriteAndCall)
// clang-format on
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ObserverRoleSurface");

  auto browseResp = session.view().browse_sync(browse(mFolderId));
  ASSERT_THAT(browseResp, ServiceResultIsGood());
  ASSERT_FALSE(browseResp.results().empty());
  EXPECT_THAT(browseResp.results()[0], Good()) << "Observer must permit Browse";
  EXPECT_FALSE(browseResp.results()[0].references().empty())
    << "a Browse that returns no references cannot distinguish a granted Role from a denied one";

  auto readResp = session.attributes().read_sync(read_value(mVariableId));
  ASSERT_THAT(readResp, ServiceResultIsGood());
  ASSERT_FALSE(readResp.results().empty());
  EXPECT_THAT(readResp.results()[0], Good()) << "Observer must permit reading live data";

  auto historyResp = session.attributes().history_read_sync(
    history_read_raw(mVariableId, surfaceHistoryStart, surfaceHistoryEnd));
  ASSERT_THAT(historyResp, ServiceResultIsGood());
  ASSERT_FALSE(historyResp.results().empty());
  EXPECT_THAT(historyResp.results()[0], Good()) << "Observer must permit reading historical data";

  EXPECT_THAT(subscribe_to_data_value(session, mVariableId), Good())
    << "Observer must permit subscribing to data";

  EXPECT_THAT(session.attributes().write_sync(WriteRequestBuilder{}.write(mVariableId, Variant{int32_t{99}})),
    WriteFailsWith(Status::BadUserAccessDenied))
    << "Observer must not permit a Write";

  auto callResp = session.methods().call_sync(CallRequestBuilder{}.call(mFolderId, mMethodId));
  ASSERT_THAT(callResp, ServiceResultIsGood());
  ASSERT_FALSE(callResp.results().empty());
  EXPECT_THAT(callResp.results()[0], HasStatus(Status::BadUserAccessDenied))
    << "Observer must not permit a Method Call - that is precisely the boundary it does not cross";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// Part 18 section 4.3 with Part 3 section 4.8.2 Table 2: ConfigureAdmin "is allowed to change
// non-security related configuration settings". The pairing with SecurityAdmin is a separation of
// duties, and merging the two is the natural simplification - one administrative Role is easier to
// configure, and it removes the one property the pair exists to provide: that whoever configures
// the server cannot also grant themselves access to it. A merged implementation passes the first
// half of this test and fails the second.
//
// The configuration change is an Attribute Write on a Node whose WriteMask opens the DisplayName
// bit and which carries no per-Node RolePermissions override, so the decision is the server's
// published ConfigureAdmin default and the refusal cannot be a zero WriteMask. The security-related
// change is a mutation of the identity-to-Role mapping (Part 18 section 4.4), and it is checked to
// have changed nothing as well as to have been refused - a server that mutates before it authorises
// has already handed over the Role.
// @verifies AC-SVR-SECADMIN-067-CONFIGUREADMIN-PERMISSIONS
// clang-format off
// The TEST_F line below must stay on ONE physical line.
TEST_F(ConfigureAdminRoleSurfaceFixture, ConfigureAdminChangesNonSecurityConfigurationButNotSecuritySettings)
// clang-format on
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ConfigureAdminSurface");

  // The non-security configuration change.
  EXPECT_THAT(
    session.attributes().write_sync(WriteRequestBuilder{}.write(
      mVariableId, Variant{LocalizedText{"", "ConfigureAdminConfigured"}}, AttributeId::DisplayName)),
    WriteSucceeds())
    << "ConfigureAdmin must permit changing a non-security configuration setting (Part 18 section 4.3)";

  auto configReadBack = session.attributes().read_sync(
    ReadRequestBuilder{}.read(mVariableId).attribute(AttributeId::DisplayName).build());
  ASSERT_THAT(configReadBack, ServiceResultIsGood());
  ASSERT_FALSE(configReadBack.results().empty());
  EXPECT_THAT(configReadBack.results()[0], Good()) << "the changed setting must be readable back";
  const auto* configuredName = configReadBack.results()[0].value().try_as<LocalizedText>();
  ASSERT_NE(configuredName, nullptr) << "DisplayName must read back as a LocalizedText";
  EXPECT_EQ(configuredName->text(), String{"ConfigureAdminConfigured"})
    << "and it must carry the value just written - an accepted Write that left the Attribute alone is "
       "a discarded Write, not a configuration change";

  // The security-related change: the identity-to-Role mapping, which is SecurityAdmin's authority
  // and not this Role's.
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("configure-admin-should-not-add-this")}}),
    Status::BadUserAccessDenied)
    << "configuration authority must not carry security authority - ConfigureAdmin must be refused a "
       "change to the identity-to-Role mapping (Part 18 section 4.3, section 4.4)";

  EXPECT_EQ(count_username_rules(
              *roleConfiguration, NodeId{0, operatorRoleId}, "configure-admin-should-not-add-this"),
    0u)
    << "and the refused change must not have been applied anyway";

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// Round-12: the certificate obligations of SVR-SECADMIN-001..023 that sit
// under the OPN path rather than the Role surface - the server's own identity,
// its replacement, chain building, Table 106 ordering and suppression, the
// None-mode exemption, and the two structural profile rules.
// ============================================================================

// Part 6 section 6.2.2 Table 43 fixes the fields an ApplicationInstance Certificate carries and which of
// them are mandatory: version "shall be V3"; the subject Common Name "shall be specified";
// subjectAltName "Shall include a uniformResourceIdentifier which is equal to the applicationUri"
// and, for a Server, "shall specify a partial or a fully qualified dNSName or a static IPAddress";
// for RSA keys keyUsage "shall include digitalSignature, nonRepudiation, keyEncipherment and
// dataEncipherment" and self-signed Certificates "shall also include keyCertSign"; extendedKeyUsage
// "shall specify serverAuth and/or clientAuth". Part 4 section 6.1.2 makes holding such a certificate the
// server's identity, which is why this is the precondition for every other security criterion here.
//
// The plausible implementation allocates a certificate carrying only what the handshake mechanically
// needs - digitalSignature and keyEncipherment, no extendedKeyUsage - because that certificate works
// against every peer that does not enforce Table 43. It fails at the first peer that does, which is
// a field failure at an integration rather than a build failure at home. The dNSName is the other
// routine omission: a URI-only SAN passes the server's own start-up checks and is refused by the
// client-side Host Name row of Part 4 Table 106.
//
// The subject is read off the CertificateStore the fixture handed to `Server::create` - the
// certificate the running server was actually created over - and then cross-checked against the
// certificate that server publishes on its secured endpoints, so this is the server's identity and
// not merely a certificate the test happens to be holding. Table 43's applicationUri EQUALITY rule
// is deliberately not asserted: this fixture configures the server's ApplicationDescription URI and
// its certificate SAN URI independently, so an equality check here would fail on the harness rather
// than on the SDK. That obligation belongs to the criteria that own the ApplicationDescription.
// @verifies AC-SVR-SECADMIN-001-APPLICATION-CERTIFICATE
TEST_F(RbacServerCertificateValidation, ServerApplicationInstanceCertificateCarriesTheTable43MandatoryFields)
{
  auto stored = mServerCertStore->try_get_application_certificates_sync();
  ASSERT_TRUE(stored.is_good()) << "the server's own certificate store must be readable: "
                                << stored.status_code().value();
  const auto applicationCertificates = std::move(stored).value();
  GTEST_LOG_(INFO) << "application certificates held by the running server's store: "
                   << applicationCertificates.size();
  ASSERT_FALSE(applicationCertificates.empty())
    << "the server must own an Application Instance Certificate at startup (Part 4 section 6.1.2) - with "
       "none, nothing below is being checked";

  const auto& certificate = applicationCertificates.front().certificate;
  ASSERT_TRUE(certificate) << "the stored application certificate entry must carry a certificate";
  ASSERT_TRUE(applicationCertificates.front().keys)
    << "and its private key - a certificate the server cannot sign with is not an identity";

  // version: "shall be V3". `version()` is the raw encoded, zero-indexed number, so v3 reads as 2.
  EXPECT_EQ(certificate->version(), 2) << "the Application Instance Certificate shall be an X.509 v3 "
                                          "Certificate (Part 6 section 6.2.2 Table 43)";
  EXPECT_FALSE(certificate->serial_number().empty())
    << "Table 43 requires a serialNumber assigned by the issuer";
  EXPECT_FALSE(certificate->subject_common_name().empty())
    << "Table 43: the subject Common Name attribute shall be specified";

  // validity: the certificate the server is running on must be in date right now.
  const auto now = DateTime::now().value();
  EXPECT_LT(certificate->validity_from().value(), now)
    << "the server's own certificate must already be valid";
  EXPECT_GT(certificate->validity_to().value(), now) << "and must not have expired";

  // subjectAltName: a URI, plus a host identity because this is a Server certificate.
  const auto sanUris = certificate->san_uris();
  GTEST_LOG_(INFO) << "SAN uniformResourceIdentifiers: " << sanUris.size()
                   << ", dNSNames: " << certificate->san_hostnames().size()
                   << ", iPAddresses: " << certificate->san_ip_addresses().size();
  EXPECT_FALSE(sanUris.empty())
    << "subjectAltName shall include a uniformResourceIdentifier equal to the applicationUri "
       "(Part 6 section 6.2.2 Table 43) - without one no peer can bind this certificate to an application";
  EXPECT_FALSE(certificate->san_hostnames().empty() && certificate->san_ip_addresses().empty())
    << "a Server shall specify a dNSName or a static IPAddress in subjectAltName (Part 6 section 6.2.2 "
       "Table 43) - the Host Name row of Part 4 Table 106 has nothing to match without one";

  // keyUsage / extendedKeyUsage / basicConstraints, for the RSA profile this server runs.
  ASSERT_EQ(certificate->key_algorithm(), CertificateKeyAlgorithm::Rsa)
    << "this fixture's server runs an RSA application certificate; the Table 43 keyUsage clause "
       "asserted below is the RSA one";
  EXPECT_TRUE(certificate->key_usage_digital_signature())
    << "RSA keyUsage shall include digitalSignature (Part 6 section 6.2.2 Table 43)";
  EXPECT_TRUE(certificate->key_usage_non_repudiation())
    << "RSA keyUsage shall include nonRepudiation (Part 6 section 6.2.2 Table 43)";
  EXPECT_TRUE(certificate->key_usage_key_encipherment())
    << "RSA keyUsage shall include keyEncipherment (Part 6 section 6.2.2 Table 43)";
  EXPECT_TRUE(certificate->key_usage_data_encipherment())
    << "RSA keyUsage shall include dataEncipherment (Part 6 section 6.2.2 Table 43)";
  EXPECT_TRUE(certificate->extended_key_usage_server_auth() || certificate->extended_key_usage_client_auth())
    << "extendedKeyUsage shall specify serverAuth and/or clientAuth (Part 6 section 6.2.2 Table 43)";

  if (certificate->self_signed())
  {
    if (certificate->basic_constraints_ca())
    {
      // Table 43 accepts cA=TRUE on a self-signed ApplicationInstance Certificate for backward
      // interoperability, but then "the pathLength shall be 0" and it includes keyCertSign.
      EXPECT_TRUE(certificate->key_usage_key_cert_sign())
        << "self-signed Certificates shall also include keyCertSign (Part 6 section 6.2.2 Table 43)";
      EXPECT_EQ(certificate->basic_constraints_path_length(), 0u)
        << "a self-signed ApplicationInstance Certificate with cA=TRUE shall carry pathLength 0 "
           "(Part 6 section 6.2.2 Table 43)";
    }
    else
    {
      // Table 43 (Table 50 in 1.05.06): "Self-signed Certificates shall also include keyCertSign", with cA
      // FALSE. An independent client refuses a self-signed server certificate without it (interoperability
      // finding 005), so the SDK's generator includes it; SD-P6-001 records the conflict with RFC 5280 and
      // DL-132 the reversal of the owner decision of 2026-10-03 (option B), which left it out.
      EXPECT_TRUE(certificate->key_usage_key_cert_sign())
        << "self-signed Certificates shall also include keyCertSign (Part 6 section 6.2.2 Table 43)";
    }
  }
  else
  {
    EXPECT_FALSE(certificate->basic_constraints_ca())
      << "the cA flag shall be FALSE for ApplicationInstance Certificates issued by a CA (Part 6 "
         "section 6.2.2 Table 43)";
  }

  // And this really is the identity the server presents: the certificate published on every secured
  // endpoint is byte-for-byte the one just examined.
  auto channel = open_channel(MessageSecurityMode::None);
  GetEndpointsRequest request;
  request.endpoint_url() = mEndpointUrl;
  auto response = channel.get_endpoints_sync(std::move(request));
  ASSERT_THAT(response, ServiceResultIsGood());
  size_t securedEndpoints = 0;
  for (size_t i = 0; i < response.endpoints().size(); ++i)
  {
    const auto& endpoint = response.endpoints()[i];
    if (endpoint.security_mode() == MessageSecurityMode::None)
    {
      continue;
    }
    ++securedEndpoints;
    EXPECT_EQ(endpoint.server_certificate(), certificate->der_encoding())
      << "endpoint " << i
      << " must publish the Application Instance Certificate the server holds - a server that "
         "publishes anything else is not identified by the certificate examined above";
  }
  GTEST_LOG_(INFO) << "secured endpoints scanned for the published certificate: " << securedEndpoints
                   << " of " << response.endpoints().size();
  EXPECT_GT(securedEndpoints, 0u)
    << "the fixture must expose at least one secured endpoint, otherwise the cross-check above ran "
       "over an empty set";
  (void)channel.try_close_sync();
}

// Part 4 section 6.1.2 requires that an administrator be able to replace the server's Application Instance
// Certificate; certificates expire, so a product that cannot rotate one has a shelf life. The
// criterion's stimulus is the OFFLINE half of that path - replace through the administrative
// interface, then restart - which `SVR-SECADMIN-002` states explicitly as an alternative to the
// runtime push path (`AC-SVR-PULLCRT-006-UPDATECERTIFICATE-GUARDS` onward).
//
// The administrative interface here is the CertificateStore itself: writing an application
// certificate of the same CertificateType replaces the stored one. The restart is a new `Server`
// over that same store, built from the same configuration by the same fixture hooks - no rebuild,
// no code change, no recompiled identity. The plausible implementation this refutes is one that
// resolves its certificate once and caches it somewhere the store cannot reach, or one that
// treats the identity as build-time configuration; either passes every test that never restarts.
//
// The observable is deliberately the wire and not the store: what the restarted server PUBLISHES on
// its secured endpoints, plus a channel that actually completes against the replacement, which is
// the proof the matching private key came with it.
// @verifies AC-SVR-SECADMIN-002-CERTIFICATE-REPLACEABLE
TEST_F(RbacServerCertificateValidation, ReplacedApplicationCertificateIsTheOneServedAfterARestart)
{
  auto original =
    mServerCertStore->try_get_application_certificate_sync(CertificateType::RsaSha256Application);
  ASSERT_TRUE(original.is_good()) << "precondition: the running server's store holds an application "
                                     "certificate: "
                                  << original.status_code().value();
  const auto originalCertificate = std::move(original).value().certificate;
  ASSERT_TRUE(originalCertificate);
  ASSERT_EQ(originalCertificate->der_encoding(), mServerCert->der_encoding())
    << "precondition: the store's application certificate is the certificate this server started on";

  // The replacement, allocated the way an administrator would obtain one, and distinct by construction.
  Crypto::Name subject;
  subject.commonName = "SECADMIN-002 Replacement Server";
  const UtcTime expiry{2050, 1, 1, 0, 0, 0};
  Crypto::SubjectAlternateName altName;
  altName.uris.push_back("urn:test:secadmin:replacement-server");
  altName.hostnames.push_back("localhost");
  altName.hostnames.push_back("127.0.0.1");
  auto allocated = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    subject, expiry, altName, CertificateType::RsaSha256Application, 2048);
  ASSERT_TRUE(allocated.is_good()) << "the replacement certificate must be allocatable: "
                                   << allocated.status_code().value();
  auto [replacementKeys, replacementCertificate] = std::move(allocated).value();
  ASSERT_TRUE(replacementCertificate);
  ASSERT_NE(replacementCertificate->der_encoding(), originalCertificate->der_encoding())
    << "precondition: the replacement must differ from the certificate in use, otherwise 'the new "
       "certificate is used' is unobservable";

  // 1. Replace, through the administrative interface.
  ua::CertificateStore::ApplicationCertificate installed;
  installed.certificateType = CertificateType::RsaSha256Application;
  installed.certificate = replacementCertificate;
  installed.keys = replacementKeys;
  auto written = mServerCertStore->try_add_to_application_certificates_sync(installed);
  ASSERT_TRUE(written.is_good()) << "the administrative interface must accept a replacement "
                                    "application certificate: "
                                 << written.status_code().value();
  auto afterWrite =
    mServerCertStore->try_get_application_certificate_sync(CertificateType::RsaSha256Application);
  ASSERT_TRUE(afterWrite.is_good()) << afterWrite.status_code().value();
  ASSERT_EQ(std::move(afterWrite).value().certificate->der_encoding(), replacementCertificate->der_encoding())
    << "the store must hold the replacement after the write - replacement that leaves the old "
       "certificate in place is not replacement";

  // The client is told about the new server identity the same way an administrator would distribute
  // it; without this the channel below would be refused by the CLIENT, not the server.
  mClientCertStore->add_to_trusted_certificates_sync(replacementCertificate);

  // 2. Restart: the same binary, the same configuration, the same store, a new Server.
  ASSERT_TRUE(mServer.has_value());
  (void)mServer->try_shutdown_sync({.grace = std::chrono::seconds{0}});
  mServer.reset();

  auto appCfg = ua::test_utils::create_test_config();
  appCfg.allowInsecureEndpoints = true;
  configure_secured_server(appCfg);
  server::ServerComponents components{.crypto = mCrypto,
    .applicationGroupCertificateStore = mServerCertStore,
    .logSink = mServerLogSink,
    .logLevel = LogLevel::Debug};
  configure_components(components);
  server::CreateConfig restartCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(appCfg)};
  configure_server_create_config(restartCfg);
  mServer.emplace(Server::create(mServerThreadPool.executor(), std::move(restartCfg), std::move(components)));

  transport::BindAddress bind;
  bind.transportProfileId = TransportProfileId::UaTcpUaScUaBinary;
  bind.address = "127.0.0.1:0";
  mListenerHandle = mServer->listen_sync(std::move(bind), {});

  ServerEndpointConfig noneEp;
  noneEp.name = "None";
  noneEp.messageSecurityMode = MessageSecurityMode::None;
  noneEp.securityPolicyId = SecurityPolicyId::None;
  noneEp.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  mServer->add_endpoint(mListenerHandle, std::move(noneEp));

  ServerEndpointConfig signEncryptEp;
  signEncryptEp.name = "Basic256Sha256_SignAndEncrypt";
  signEncryptEp.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  signEncryptEp.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  signEncryptEp.userIdentityTokens.push_back(
    create_user_token_policy(UserTokenType::Anonymous, SecurityPolicyId::None));
  mServer->add_endpoint(mListenerHandle, std::move(signEncryptEp));

  mServer->start_sync();
  auto urls = mServer->advertised_urls(mListenerHandle);
  ASSERT_FALSE(urls.empty()) << "the restarted server must be reachable";
  mEndpointUrl = urls.front().str();

  // 3. The new certificate is what subsequent channels get.
  auto discovery = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  GetEndpointsRequest request;
  request.endpoint_url() = mEndpointUrl;
  auto response = discovery.get_endpoints_sync(std::move(request));
  ASSERT_THAT(response, ServiceResultIsGood());
  size_t securedEndpoints = 0;
  for (size_t i = 0; i < response.endpoints().size(); ++i)
  {
    const auto& endpoint = response.endpoints()[i];
    if (endpoint.security_mode() == MessageSecurityMode::None)
    {
      continue;
    }
    ++securedEndpoints;
    EXPECT_EQ(endpoint.server_certificate(), replacementCertificate->der_encoding())
      << "endpoint " << i
      << " must publish the REPLACEMENT certificate after the restart (Part 4 section 6.1.2)";
    EXPECT_NE(endpoint.server_certificate(), originalCertificate->der_encoding())
      << "endpoint " << i
      << " is still publishing the superseded certificate - the server did not take the replacement "
         "from the store";
  }
  GTEST_LOG_(INFO) << "secured endpoints on the restarted server: " << securedEndpoints << " of "
                   << response.endpoints().size();
  ASSERT_GT(securedEndpoints, 0u)
    << "the restarted server must expose a secured endpoint, otherwise nothing above was checked";
  (void)discovery.try_close_sync();

  // And it is usable, not merely published: a channel that completes proves the private key that
  // came with the replacement is the one the server signs with.
  ua::client::CoreClient::OpenChannelConfig secured;
  secured.endpointUrl = mEndpointUrl;
  secured.securityMode = MessageSecurityMode::SignAndEncrypt;
  secured.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  secured.serverCertificate = replacementCertificate;
  auto opened = mClient->core().try_open_channel_sync(std::move(secured));
  EXPECT_TRUE(opened.is_good())
    << "a SignAndEncrypt channel must open against the replaced certificate - replacement that "
       "cannot be used is not replacement; got "
    << opened.status_code().value();
  if (opened.is_good())
  {
    auto channel = std::move(opened).value();
    (void)channel.try_close_sync();
  }
}

// Part 4 section 6.1.3: "When building a chain each Certificate in the chain shall be validated back to a
// CA with a self-signed Certificate (a.k.a. a root CA). If any validation error occurs then the
// trust check fails." and "Processing fails with Bad_SecurityChecksFailed if an element in the chain
// cannot be found."
//
// "Any" is the word with teeth. The shortcut this forbids is the one every validator is tempted by:
// find the presented certificate - or the nearest certificate above it - in the trust list, accept,
// and never walk the rest of the issuers. That shortcut passes every test built on a directly
// trusted certificate and fails only against a chain whose INTERMEDIATE is the broken link, which is
// precisely the case an intermediate CA exists to make manageable.
//
// Three broken chains, one control, all four built the same way and all four differing from the
// control in exactly one link, so a refusal is attributable to that link. Verdicts come from the
// server's own `CertificateStore` - the object `SecurityPolicy::validate_certificate_async` hands
// every OPN certificate to - with an explicit empty option set so no suppression is in play.
// @verifies AC-SVR-SECADMIN-003-CHAIN-TO-ROOT
TEST_F(RbacServerCertificateValidation, EveryLinkOfAChainIsValidatedBackToASelfSignedTrustedRoot)
{
  const TrustListValidationOptions noSuppression{};

  // Control: root trusted, intermediate available for chain building, leaf beneath the intermediate.
  const auto rootKeys = new_rsa_keys(2048);
  const auto intermediateKeys = new_rsa_keys(2048);
  const auto leafKeys = new_rsa_keys(2048);
  ASSERT_TRUE(rootKeys && intermediateKeys && leafKeys);
  const auto root = allocate(root_ca_params(rootKeys, "6501", "SECADMIN-003 Root CA"), "root CA");
  ASSERT_TRUE(root);
  auto intermediateParams = root_ca_params(intermediateKeys, "6502", "SECADMIN-003 Intermediate CA");
  intermediateParams.issuer = root;
  intermediateParams.issuerKeys = rootKeys;
  const auto intermediate = allocate(intermediateParams, "intermediate CA");
  ASSERT_TRUE(intermediate);
  const auto leaf =
    allocate(conformant_leaf_params(
               intermediate, intermediateKeys, leafKeys, "6503", "SECADMIN-003 Chain Leaf", "chain003"),
      "leaf under the intermediate");
  ASSERT_TRUE(leaf);
  mServerCertStore->add_to_trusted_certificates_sync(root);
  mServerCertStore->add_to_issuer_certificates_sync(intermediate);

  const auto control = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(leaf, {}, noSuppression));
  ASSERT_TRUE(control.is_good())
    << "precondition: a complete, in-date chain to a trusted self-signed root must be accepted, "
       "otherwise the three refusals below prove nothing about chain validation; got "
    << control.status_code().value();

  // (a) The intermediate is missing. Same shape of chain, same trusted root, but the only
  // certificate that can join the leaf to the root is nowhere the server can reach it.
  const auto orphanRootKeys = new_rsa_keys(2048);
  const auto orphanIntermediateKeys = new_rsa_keys(2048);
  const auto orphanLeafKeys = new_rsa_keys(2048);
  ASSERT_TRUE(orphanRootKeys && orphanIntermediateKeys && orphanLeafKeys);
  const auto orphanRoot =
    allocate(root_ca_params(orphanRootKeys, "6504", "SECADMIN-003 Orphan Root CA"), "root CA");
  ASSERT_TRUE(orphanRoot);
  auto orphanIntermediateParams =
    root_ca_params(orphanIntermediateKeys, "6505", "SECADMIN-003 Orphan Intermediate CA");
  orphanIntermediateParams.issuer = orphanRoot;
  orphanIntermediateParams.issuerKeys = orphanRootKeys;
  const auto orphanIntermediate = allocate(orphanIntermediateParams, "intermediate CA");
  ASSERT_TRUE(orphanIntermediate);
  const auto orphanLeaf = allocate(conformant_leaf_params(orphanIntermediate,
                                     orphanIntermediateKeys,
                                     orphanLeafKeys,
                                     "6506",
                                     "SECADMIN-003 Orphan Leaf",
                                     "orphan003"),
    "leaf whose intermediate is absent");
  ASSERT_TRUE(orphanLeaf);
  mServerCertStore->add_to_trusted_certificates_sync(orphanRoot);
  // Deliberately NOT added: orphanIntermediate.
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(orphanLeaf, {}, noSuppression))
      .is_bad())
    << "a chain with a missing element must fail (Part 4 section 6.1.3 - 'Processing fails with "
       "Bad_SecurityChecksFailed if an element in the chain cannot be found'); accepting it means "
       "the chain was never walked";

  // (b) The chain is complete but terminates in a root nobody trusts. Both CAs are available for
  // chain building, so the chain BUILDS - the only thing wrong with it is where it ends.
  const auto strangerRootKeys = new_rsa_keys(2048);
  const auto strangerIntermediateKeys = new_rsa_keys(2048);
  const auto strangerLeafKeys = new_rsa_keys(2048);
  ASSERT_TRUE(strangerRootKeys && strangerIntermediateKeys && strangerLeafKeys);
  const auto strangerRoot =
    allocate(root_ca_params(strangerRootKeys, "6507", "SECADMIN-003 Stranger Root CA"), "stranger root CA");
  ASSERT_TRUE(strangerRoot);
  auto strangerIntermediateParams =
    root_ca_params(strangerIntermediateKeys, "6508", "SECADMIN-003 Stranger Intermediate CA");
  strangerIntermediateParams.issuer = strangerRoot;
  strangerIntermediateParams.issuerKeys = strangerRootKeys;
  const auto strangerIntermediate = allocate(strangerIntermediateParams, "stranger intermediate CA");
  ASSERT_TRUE(strangerIntermediate);
  const auto strangerLeaf = allocate(conformant_leaf_params(strangerIntermediate,
                                       strangerIntermediateKeys,
                                       strangerLeafKeys,
                                       "6509",
                                       "SECADMIN-003 Stranger Leaf",
                                       "stranger003"),
    "leaf under an untrusted root");
  ASSERT_TRUE(strangerLeaf);
  mServerCertStore->add_to_issuer_certificates_sync(strangerIntermediate);
  mServerCertStore->add_to_issuer_certificates_sync(strangerRoot);
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(strangerLeaf, {}, noSuppression))
      .is_bad())
    << "a chain that builds all the way to a self-signed root but reaches no TRUSTED certificate "
       "must fail (Part 4 section 6.1.3) - chain-building material is not a trust anchor";

  // (c) The chain is complete and the root is trusted, but the intermediate has expired. The leaf's
  // own dates are good and the root's are good; the only invalid link is the middle one. A validator
  // that checks the dates of the presented certificate and then only the trust status of its issuers
  // accepts this, and that is the case revocation and expiry of an intermediate exist to cover.
  const auto staleRootKeys = new_rsa_keys(2048);
  const auto staleIntermediateKeys = new_rsa_keys(2048);
  const auto staleLeafKeys = new_rsa_keys(2048);
  ASSERT_TRUE(staleRootKeys && staleIntermediateKeys && staleLeafKeys);
  const auto staleRoot =
    allocate(root_ca_params(staleRootKeys, "6510", "SECADMIN-003 Stale Root CA"), "root CA");
  ASSERT_TRUE(staleRoot);
  auto staleIntermediateParams =
    root_ca_params(staleIntermediateKeys, "6511", "SECADMIN-003 Expired Intermediate CA");
  staleIntermediateParams.issuer = staleRoot;
  staleIntermediateParams.issuerKeys = staleRootKeys;
  staleIntermediateParams.from = DateTime{DateTime::now().value() - std::chrono::days{60}};
  staleIntermediateParams.to = DateTime{DateTime::now().value() - std::chrono::days{1}};
  const auto staleIntermediate = allocate(staleIntermediateParams, "expired intermediate CA");
  ASSERT_TRUE(staleIntermediate);
  auto staleLeafParams = conformant_leaf_params(
    staleIntermediate, staleIntermediateKeys, staleLeafKeys, "6512", "SECADMIN-003 Stale Leaf", "stale003");
  const auto staleLeaf = allocate(staleLeafParams, "in-date leaf under an expired intermediate");
  ASSERT_TRUE(staleLeaf);
  ASSERT_GT(staleLeaf->validity_to().value(), DateTime::now().value())
    << "precondition: the leaf itself must still be in date, so only the intermediate can refuse it";
  mServerCertStore->add_to_trusted_certificates_sync(staleRoot);
  mServerCertStore->add_to_issuer_certificates_sync(staleIntermediate);
  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(staleLeaf, {}, noSuppression))
      .is_bad())
    << "a validation error ANYWHERE in the chain fails the trust check (Part 4 section 6.1.3) - an expired "
       "intermediate is such an error, however healthy the leaf and the root are";
}

// Part 4 Table 106 "specifies the steps used to validate a Certificate in the order that they shall
// be followed", and "Processing halts if an error occurs". The order is not cosmetic: it decides
// which error a peer is told about, and Table 106 marks some rows suppressible and others not, so a
// validator that runs the cheap checks first can report - and, with suppression configured, waive -
// a suppressible error on a certificate that an ordered validator would already have stopped on for
// a non-suppressible one.
//
// The pair chosen here is Trust List Check (row 5, no suppression clause) against Validity Period
// (row 6, "This error may be suppressed"), because they are adjacent and their relative order is
// exactly the one a date-first implementation inverts.
//
// The expected codes are not hard-coded: they are read off the server's own verdicts on two
// single-fault certificates, so the test pins the ORDER and nothing else, and cannot manufacture a
// defect out of a conforming server that happens to name its rows differently. The premise that the
// two single-fault verdicts really are distinguishable is asserted before anything depends on it.
// @verifies AC-SVR-SECADMIN-004-VALIDATION-ORDER
TEST_F(RbacServerCertificateValidation, TheReportedErrorIsTheFirstFailingTable106StepNotAnArbitraryOne)
{
  const TrustListValidationOptions noSuppression{};

  const auto trustedCaKeys = new_rsa_keys(2048);
  const auto strangerCaKeys = new_rsa_keys(2048);
  ASSERT_TRUE(trustedCaKeys && strangerCaKeys);
  const auto trustedCa =
    allocate(root_ca_params(trustedCaKeys, "6601", "SECADMIN-004 Trusted CA"), "trusted CA");
  const auto strangerCa =
    allocate(root_ca_params(strangerCaKeys, "6602", "SECADMIN-004 Stranger CA"), "stranger CA");
  ASSERT_TRUE(trustedCa && strangerCa);
  mServerCertStore->add_to_trusted_certificates_sync(trustedCa);
  // The stranger is chain-building material only, so its leaves fail the Trust List row rather than
  // the Build Certificate Chain row - the row this test needs them to fail.
  mServerCertStore->add_to_issuer_certificates_sync(strangerCa);

  // Single fault: Validity Period. Issued by the CA the server trusts, so row 5 passes.
  const auto expiredKeys = new_rsa_keys(2048);
  ASSERT_TRUE(expiredKeys);
  auto expiredParams = conformant_leaf_params(
    trustedCa, trustedCaKeys, expiredKeys, "6603", "SECADMIN-004 Expired Leaf", "expired004");
  expiredParams.from = DateTime{DateTime::now().value() - std::chrono::days{30}};
  expiredParams.to = DateTime{DateTime::now().value() - std::chrono::days{1}};
  const auto expiredOnly = allocate(expiredParams, "expired-only leaf");
  ASSERT_TRUE(expiredOnly);

  // Single fault: Trust List Check. In date, so row 6 passes.
  const auto untrustedKeys = new_rsa_keys(2048);
  ASSERT_TRUE(untrustedKeys);
  const auto untrustedOnly = allocate(
    conformant_leaf_params(
      strangerCa, strangerCaKeys, untrustedKeys, "6604", "SECADMIN-004 Untrusted Leaf", "untrusted004"),
    "untrusted-only leaf");
  ASSERT_TRUE(untrustedOnly);

  // Both faults at once: untrusted AND expired.
  const auto bothKeys = new_rsa_keys(2048);
  ASSERT_TRUE(bothKeys);
  auto bothParams = conformant_leaf_params(
    strangerCa, strangerCaKeys, bothKeys, "6605", "SECADMIN-004 Untrusted Expired Leaf", "both004");
  bothParams.from = DateTime{DateTime::now().value() - std::chrono::days{30}};
  bothParams.to = DateTime{DateTime::now().value() - std::chrono::days{1}};
  const auto bothFaults = allocate(bothParams, "untrusted and expired leaf");
  ASSERT_TRUE(bothFaults);

  const auto expiredVerdict = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(expiredOnly, {}, noSuppression));
  const auto untrustedVerdict = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(untrustedOnly, {}, noSuppression));
  ASSERT_TRUE(expiredVerdict.is_bad()) << "precondition: an expired leaf must be refused";
  ASSERT_TRUE(untrustedVerdict.is_bad()) << "precondition: an untrusted leaf must be refused";
  ASSERT_NE(expiredVerdict.status_code().as_status(), untrustedVerdict.status_code().as_status())
    << "precondition: the two single-fault certificates must produce DISTINGUISHABLE codes, "
       "otherwise no ordering could be observed and the assertion below would be vacuous";

  const auto bothVerdict = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(bothFaults, {}, noSuppression));
  ASSERT_TRUE(bothVerdict.is_bad()) << "a certificate failing two Table 106 rows must be refused";
  EXPECT_EQ(bothVerdict.status_code().as_status(), untrustedVerdict.status_code().as_status())
    << "a certificate failing both the Trust List Check (Table 106 row 5) and the Validity Period "
       "check (row 6) must be reported as the FIRST failing step - processing halts there";
  EXPECT_NE(bothVerdict.status_code().as_status(), expiredVerdict.status_code().as_status())
    << "reporting the Validity Period error means the later row ran first; that is the ordering "
       "inversion Table 106 forbids, and it is the one that lets a suppressible error stand in for a "
       "non-suppressible one";
}

// Part 4 Table 106 marks each validation row suppressible or not, one row at a time: Validity Period
// and Find Revocation List say "This error may be suppressed"; Certificate Structure, Build
// Certificate Chain, Signature, URI and Revocation Check say it may not, and the Trust List Check
// row carries no suppression clause at all. `SVR-SECADMIN-007` restates the split.
//
// The implementation this forbids is the single global lenient switch - "accept anything the
// administrator has told us not to worry about" - which is the natural shape because every
// suppression is configured in the same place. Under it, turning off the noise from expired
// certificates also turns off the trust list, and the server's whole PKI configuration becomes
// decorative.
//
// So: every suppression the option set has to offer is turned on at once, and both certificates are
// presented under that one configuration. Revocation is left to
// `AC-SVR-SECADMIN-017-SUPPRESSION-ASYMMETRY`, which owns the Find-Revocation-List / Revocation-Check
// pair; the non-suppressible row exercised here is the Trust List Check.
// @verifies AC-SVR-SECADMIN-007-SUPPRESSION-TABLE
TEST_F(RbacServerCertificateValidation, EverySuppressionEnabledStillRefusesANonSuppressibleFailure)
{
  const TrustListValidationOptions noSuppression{};
  // Every suppress bit the SDK's option set defines, all at once.
  const TrustListValidationOptions everySuppression{
    TrustListValidationOptions::Bit::SuppressCertificateExpired,
    TrustListValidationOptions::Bit::SuppressHostNameInvalid,
    TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown,
    TrustListValidationOptions::Bit::SuppressIssuerCertificateExpired,
    TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown};

  const auto trustedCaKeys = new_rsa_keys(2048);
  const auto strangerCaKeys = new_rsa_keys(2048);
  ASSERT_TRUE(trustedCaKeys && strangerCaKeys);
  const auto trustedCa =
    allocate(root_ca_params(trustedCaKeys, "6701", "SECADMIN-007 Trusted CA"), "trusted CA");
  const auto strangerCa =
    allocate(root_ca_params(strangerCaKeys, "6702", "SECADMIN-007 Stranger CA"), "stranger CA");
  ASSERT_TRUE(trustedCa && strangerCa);
  mServerCertStore->add_to_trusted_certificates_sync(trustedCa);
  mServerCertStore->add_to_issuer_certificates_sync(strangerCa);

  // The suppressible failure: Validity Period (Table 106 row 6).
  const auto expiredKeys = new_rsa_keys(2048);
  ASSERT_TRUE(expiredKeys);
  auto expiredParams = conformant_leaf_params(
    trustedCa, trustedCaKeys, expiredKeys, "6703", "SECADMIN-007 Expired Leaf", "expired007");
  expiredParams.from = DateTime{DateTime::now().value() - std::chrono::days{30}};
  expiredParams.to = DateTime{DateTime::now().value() - std::chrono::days{1}};
  const auto expiredLeaf = allocate(expiredParams, "expired leaf under the trusted CA");
  ASSERT_TRUE(expiredLeaf);

  // The non-suppressible failure: Trust List Check (Table 106 row 5).
  const auto untrustedKeys = new_rsa_keys(2048);
  ASSERT_TRUE(untrustedKeys);
  const auto untrustedLeaf = allocate(
    conformant_leaf_params(
      strangerCa, strangerCaKeys, untrustedKeys, "6704", "SECADMIN-007 Untrusted Leaf", "untrusted007"),
    "in-date leaf under an untrusted CA");
  ASSERT_TRUE(untrustedLeaf);

  // Premise: with nothing suppressed both certificates are refused, so anything accepted below is
  // suppression doing it and not a validator that accepts everything.
  ASSERT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(expiredLeaf, {}, noSuppression))
      .is_bad())
    << "precondition: an expired certificate must be refused when nothing is suppressed";
  ASSERT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(untrustedLeaf, {}, noSuppression))
      .is_bad())
    << "precondition: an untrusted certificate must be refused when nothing is suppressed";

  const auto suppressedExpiry = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(expiredLeaf, {}, everySuppression));
  EXPECT_TRUE(suppressedExpiry.is_good())
    << "the Validity Period row of Table 106 says 'This error may be suppressed', so with "
       "SuppressCertificateExpired configured the certificate must be accepted; got "
    << suppressedExpiry.status_code().value();

  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(untrustedLeaf, {}, everySuppression))
      .is_bad())
    << "no configuration may waive the Trust List Check - Table 106 attaches a suppression clause to "
       "individual rows and not to this one, so a certificate reaching no trust anchor must still be "
       "refused with every suppression the server offers turned on";
}

// Part 4 section 6.1.3 read with `SVR-SECADMIN-015`: a None-mode endpoint "accept[s] *any* client (or no
// client cert at all) at the OPN layer. The ApplicationInstanceCertificate is not validated." This
// is the endpoint-layer statement of the rule `AC-SVR-SC-008-NONE-IGNORES-CERT` and
// `AC-SVR-SESS-010-NONE-IGNORES-CERT` carry at the channel and session layers.
//
// The implementation this refutes hangs certificate validation off the connection rather than off
// the security policy - a single "validate the peer" step at the top of the OPN handler, before the
// mode is consulted. It looks harmless and it breaks None entirely: a None endpoint exists so that a
// client with no PKI relationship to this server can reach the unsecured surface at all, and a
// client whose certificate the server would refuse is exactly the client that needs it.
//
// On the wire, "presenting none" and "presenting an untrusted certificate" are the same OPN on a
// None channel - no certificate is exchanged under SecurityPolicy None - so the falsifiable form of
// the stimulus is two identities the server demonstrably WOULD refuse, each shown to be refused on
// the secured endpoint and admitted on the None endpoint of the same running server. The two are
// broken in different ways (trust, and validity) so no single-cause exemption explains both.
// @verifies AC-SVR-SECADMIN-015-NONE-IGNORES-CERT
TEST_F(RbacServerCertificateValidation, NoneModeEndpointAdmitsIdentitiesTheSecuredEndpointRefuses)
{
  const auto strangerCaKeys = new_rsa_keys(2048);
  ASSERT_TRUE(strangerCaKeys);
  const auto strangerCa =
    allocate(root_ca_params(strangerCaKeys, "6901", "SECADMIN-015 Stranger CA"), "stranger CA");
  ASSERT_TRUE(strangerCa);
  // Deliberately never added to the server's trust or issuer lists.

  const auto untrustedKeys = new_rsa_keys(2048);
  ASSERT_TRUE(untrustedKeys);
  const auto untrustedLeaf = allocate(
    conformant_leaf_params(
      strangerCa, strangerCaKeys, untrustedKeys, "6902", "SECADMIN-015 Untrusted Leaf", "none015untrusted"),
    "untrusted leaf");
  ASSERT_TRUE(untrustedLeaf);

  const auto expiredKeys = new_rsa_keys(2048);
  ASSERT_TRUE(expiredKeys);
  auto expiredParams = conformant_leaf_params(
    strangerCa, strangerCaKeys, expiredKeys, "6903", "SECADMIN-015 Expired Leaf", "none015expired");
  expiredParams.from = DateTime{DateTime::now().value() - std::chrono::days{30}};
  expiredParams.to = DateTime{DateTime::now().value() - std::chrono::days{1}};
  const auto expiredLeaf = allocate(expiredParams, "expired leaf");
  ASSERT_TRUE(expiredLeaf);

  // The premise: this server really would refuse both of these identities when it evaluates them.
  // Without it, "the None endpoint accepted them" would say nothing about ignoring the certificate.
  ASSERT_EQ(channel_status_as(
              untrustedLeaf, untrustedKeys, "none015untrusted_secured", MessageSecurityMode::SignAndEncrypt),
    Status::BadSecurityChecksFailed)
    << "precondition: the secured endpoint of this same server must refuse the untrusted identity";
  ASSERT_EQ(channel_status_as(
              expiredLeaf, expiredKeys, "none015expired_secured", MessageSecurityMode::SignAndEncrypt),
    Status::BadSecurityChecksFailed)
    << "precondition: the secured endpoint of this same server must refuse the expired identity";

  // The obligation: the None endpoint does not evaluate the certificate at all.
  EXPECT_EQ(channel_status_as(untrustedLeaf, untrustedKeys, "none015untrusted", MessageSecurityMode::None),
    Status::Good)
    << "a None-mode endpoint accepts any client at the OPN layer - the ApplicationInstanceCertificate "
       "is not validated (Part 4 section 6.1.3, SVR-SECADMIN-015)";
  EXPECT_EQ(
    channel_status_as(expiredLeaf, expiredKeys, "none015expired", MessageSecurityMode::None), Status::Good)
    << "and the same holds for an expired one - a None endpoint that refuses a certificate it never "
       "exchanged has moved a security check above the security policy that governs it";
}

// Part 4 Table 106 splits revocation across two rows, and only the first is suppressible. Find
// Revocation List - "This check fails if this list is not available (i.e. a network interruption
// prevents the application from accessing the list)" - says "This error may be suppressed".
// Revocation Check - "The Certificate has been revoked and may not be used" - says "This error may
// not be suppressed."
//
// One flag governing both is the implementation this forbids, and it is the natural one: both are
// "revocation problems", both are configured in the same place, and an air-gapped deployment that
// cannot reach a CRL distribution point has a legitimate reason to ask for one of them to be waived.
// Granting that request with a single switch turns a deployment convenience into a way to accept
// revoked certificates - and revocation is the only mechanism a PKI has for withdrawing an identity
// before its expiry date.
//
// On the criterion's wording: "accepted under suppression, reporting `Bad_SecurityChecksFailed` to
// the client" names two mutually exclusive outcomes. Table 106 governs, and it says the row may be
// suppressed, so what is asserted here is acceptance. `Bad_SecurityChecksFailed` is the code Table
// 106 attaches to that row when it is NOT suppressed, which is
// `AC-SVR-SECADMIN-006-CHECKS-FAILED-SUBSTITUTED`'s obligation and is asserted there.
// @verifies AC-SVR-SECADMIN-017-SUPPRESSION-ASYMMETRY
TEST_F(RbacServerCertificateValidation, AMissingRevocationListIsSuppressibleButARevokedCertificateIsNot)
{
  const TrustListValidationOptions checkOnly{TrustListValidationOptions::Bit::CheckRevocationStatusOffline};
  const TrustListValidationOptions checkAndSuppress{
    TrustListValidationOptions::Bit::CheckRevocationStatusOffline,
    TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown,
    TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown};

  const auto caKeys = new_rsa_keys(2048);
  ASSERT_TRUE(caKeys);
  const auto ca = allocate(root_ca_params(caKeys, "7101", "SECADMIN-017 CA"), "issuing CA");
  ASSERT_TRUE(ca);
  mServerCertStore->add_to_trusted_certificates_sync(ca);

  const auto revokedKeys = new_rsa_keys(2048);
  const auto survivorKeys = new_rsa_keys(2048);
  ASSERT_TRUE(revokedKeys && survivorKeys);
  const auto revokedLeaf = allocate(
    conformant_leaf_params(ca, caKeys, revokedKeys, "7102", "SECADMIN-017 Revoked Leaf", "revoked017"),
    "leaf to be revoked");
  const auto survivorLeaf = allocate(
    conformant_leaf_params(ca, caKeys, survivorKeys, "7103", "SECADMIN-017 Survivor Leaf", "survivor017"),
    "leaf that stays valid");
  ASSERT_TRUE(revokedLeaf && survivorLeaf);

  // Arm 1 - the CRL cannot be located. No CRL for this CA has been installed and revocation checking
  // is on, so the Find Revocation List row is the one that fails.
  const auto unsuppressed = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(revokedLeaf, {}, checkOnly));
  ASSERT_TRUE(unsuppressed.is_bad())
    << "precondition: with revocation checking enabled and no CRL available for the issuer, the Find "
       "Revocation List row of Table 106 must fail - if it does not, there is no suppressible error "
       "here and the asymmetry below cannot be observed";
  const auto suppressed = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(revokedLeaf, {}, checkAndSuppress));
  EXPECT_TRUE(suppressed.is_good())
    << "'Find Revocation List' is marked 'This error may be suppressed' in Table 106, so with that "
       "suppression configured the certificate must be accepted; got "
    << suppressed.status_code().value();

  // Arm 2 - the CRL is found and the certificate is on it. Same configuration, every revocation
  // suppression still enabled.
  auto crl = mCrypto->try_create_crl_sync(ca, caKeys, {revokedLeaf->serial_number()});
  ASSERT_TRUE(crl.is_good()) << "the test must be able to revoke a certificate it issued: "
                             << crl.status_code().value();
  mServerCertStore->add_to_trusted_crls_sync(std::move(crl).value());

  EXPECT_TRUE(
    mServerCertStore
      ->try_validate_certificate_sync(ua::test::make_validation_request(revokedLeaf, {}, checkAndSuppress))
      .is_bad())
    << "'Revocation Check' is marked 'This error may not be suppressed' in Table 106 - a certificate "
       "the issuer's CRL lists must be refused under EVERY configuration, including the one that "
       "just waived the missing-CRL error";

  // Control: the same CA, the same CRL, the same suppressing configuration - a sibling the CRL does
  // not list is accepted. Without this the refusal above could be the CRL's mere presence.
  const auto survivor = mServerCertStore->try_validate_certificate_sync(
    ua::test::make_validation_request(survivorLeaf, {}, checkAndSuppress));
  EXPECT_TRUE(survivor.is_good())
    << "a certificate the CRL does not list must still be accepted - otherwise the refusal above is "
       "not attributable to the revocation entry; got "
    << survivor.status_code().value();
}

// Part 4 section 6.1.3: "ApplicationInstanceCertificates shall not be used in a Client or Server until they
// have been evaluated and marked as trusted." Presence and trust are two states, not one.
//
// The implementation this refutes conflates them, and the shape it takes is a certificate directory
// the validator loads wholesale. That is not an obviously wrong design - everything in the folder is
// there because an administrator put it there - until you notice the other thing the store holds:
// the rejected list, which exists precisely so that certificates the server has already turned away
// can be reviewed and, if the administrator agrees, promoted
// (`AC-SVR-PULLCRT-021-GETREJECTEDLIST-GUARDS`). Conflating presence with trust trusts every peer
// that has ever attempted a connection.
//
// The stimulus goes over the wire because "attempt to connect with it" is what the criterion asks
// for, and the promotion at the end is what makes the refusal attributable to the trust marking: the
// same certificate, the same server, the same endpoint, accepted the moment it is marked trusted.
// @verifies AC-SVR-SECADMIN-020-TRUST-BEFORE-USE
TEST_F(RbacServerCertificateValidation, ACertificateHeldInTheStoreButNotMarkedTrustedIsRefused)
{
  // Self-signed, so this one certificate is the peer's whole trust path and the trust decision has
  // nowhere else to come from.
  const auto peerKeys = new_rsa_keys(2048);
  ASSERT_TRUE(peerKeys);
  auto peerParams = root_ca_params(peerKeys, "7201", "SECADMIN-020 Pending Peer");
  peerParams.basicConstraint.pathLength = 0;
  peerParams.keyUsage.nonRepudiation = true;
  peerParams.keyUsage.keyEncipherment = true;
  peerParams.keyUsage.dataEncipherment = true;
  peerParams.keyUsage.clientAuth = true;
  peerParams.subjectAlternateName.uris.push_back(identity_uri("pending020"));
  peerParams.subjectAlternateName.hostnames.push_back("localhost");
  const auto peerCert = allocate(peerParams, "pending peer certificate");
  ASSERT_TRUE(peerCert);

  // In the store - and only in the holding pen.
  auto stored = mServerCertStore->try_add_to_rejected_certificates_sync(peerCert);
  ASSERT_TRUE(stored.is_good()) << "the store must be able to hold a certificate that is not trusted: "
                                << stored.status_code().value();

  auto rejected = mServerCertStore->try_get_rejected_certificates_sync();
  ASSERT_TRUE(rejected.is_good()) << rejected.status_code().value();
  const auto rejectedList = std::move(rejected).value();
  GTEST_LOG_(INFO) << "certificates held in the server's rejected list: " << rejectedList.size();
  bool held = false;
  for (const auto& entry : rejectedList)
  {
    if (entry && entry->serial_number() == peerCert->serial_number())
    {
      held = true;
    }
  }
  ASSERT_TRUE(held) << "precondition: the certificate really is in the server's store - a refusal "
                       "below would otherwise be about a certificate the store never received";

  auto trusted = mServerCertStore->try_get_trusted_certificates_sync();
  ASSERT_TRUE(trusted.is_good()) << trusted.status_code().value();
  for (const auto& entry : std::move(trusted).value())
  {
    ASSERT_FALSE(entry && entry->serial_number() == peerCert->serial_number())
      << "precondition: and it is NOT in the trusted list - holding a certificate must not have "
         "marked it trusted";
  }

  EXPECT_EQ(channel_status_as(peerCert, peerKeys, "pending020"), Status::BadSecurityChecksFailed)
    << "a certificate that has not been evaluated and marked as trusted shall not be used (Part 4 "
       "section 6.1.3) - presence in the store is not trust";

  // Promotion. Nothing about the certificate changes; only its marking does.
  mServerCertStore->add_to_trusted_certificates_sync(peerCert);
  EXPECT_EQ(channel_status_as(peerCert, peerKeys, "promoted020"), Status::Good)
    << "and once marked trusted the same certificate must be accepted - this is what makes the "
       "refusal above attributable to the trust marking rather than to the certificate";
}

// ============================================================================
// Security review 2026-09-28: the RoleType baseline copied onto AddRole-created Roles grants Role
// management to SecurityAdmin alone (Part 3 Table 2 / Part 18), and a UserName identity-mapping
// rule names a UserName token only (Part 18 section 4.4.4 Table 10).
// ============================================================================

// The same caller first holds SecurityAdmin and ConfigureAdmin, creates a Role and manages it
// (control); once SecurityAdmin is taken away, the still-ConfigureAdmin caller is refused the very
// same management call on that Role, and the refusal changed nothing.
// @relation(AC-SVR-SECADMIN-037-ROLE-MANAGEMENT-IS-SECURITY-ADMIN-ONLY, scope=function)
TEST_F(RbacSecurityAdminAuthorityFixture, ConfigureAdminAloneCannotManageARoleCreatedByAddRole)
{
  NodeId customRole;
  NodeId customAddIdentity;
  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "SecurityAdminCreatesRole");
    customRole = add_role(session, "ReviewManagedRole", namespace_uri_for_index(1));
    ASSERT_FALSE(customRole.is_null()) << "AddRole by a SecurityAdmin must succeed";
    customAddIdentity = find_child_node_id(session, customRole, "AddIdentity");
    ASSERT_FALSE(customAddIdentity.is_null()) << "the new Role carries the RoleType AddIdentity Method";
    EXPECT_EQ(
      call_status(
        session, customRole, customAddIdentity, {Variant{username_rule("managed-by-security-admin")}}),
      Status::Good)
      << "control: a SecurityAdmin Session manages the Role it created";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }
  EXPECT_EQ(count_username_rules(*roleConfiguration, customRole, "managed-by-security-admin"), 1u);

  ASSERT_TRUE(roleConfiguration->add_role(
    well_known_role_for_user(ObjectId::WellKnownRole_SecurityAdmin, 7, "somebody-else-entirely")))
    << "the SecurityAdmin definition must be replaceable";
  ASSERT_EQ(count_username_rules(*roleConfiguration, NodeId{0, configureAdminRoleId}, securityAdminUser), 1u)
    << "the caller is still ConfigureAdmin";

  {
    auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ConfigureAdminOnCustomRole");
    EXPECT_EQ(
      call_status(
        session, customRole, customAddIdentity, {Variant{username_rule("managed-by-configure-admin")}}),
      Status::BadUserAccessDenied)
      << "ConfigureAdmin may browse and read a custom Role but not change who holds it; before the fix "
         "AddRole copied a baseline that granted ConfigureAdmin every bit";
    (void)session.try_close_sync();
    (void)channel.try_close_sync();
  }
  EXPECT_EQ(count_username_rules(*roleConfiguration, customRole, "managed-by-configure-admin"), 0u)
    << "the refused call must have changed nothing";
}

/// SecurityAdmin is mapped by a UserName rule naming "operator"; the authenticator presents an X.509
/// identity whose user id (its certificate's common name) is the same string.
class RbacUserNameRuleSameNameX509Fixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    ASSERT_TRUE(
      config.add_role(well_known_role_for_user(ObjectId::WellKnownRole_SecurityAdmin, 7, "operator")))
      << "SecurityAdmin slot must register";
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::X509, "operator", std::unordered_map<std::string, std::string>{});
  }
};

/// The control: the same rule, and a UserName identity of that name.
class RbacUserNameRuleSameNameUserNameFixture : public RbacUserNameRuleSameNameX509Fixture
{
protected:
  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, "operator", std::unordered_map<std::string, std::string>{});
  }
};

// @relation(AC-SVR-AUTHZ-018-USERNAME-CRITERION-BINDS-THE-TOKEN-KIND, scope=function)
TEST_F(RbacUserNameRuleSameNameX509Fixture, AnX509IdentityWhoseNameMatchesAUserNameRuleHoldsNoneOfItsRoles)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "X509SameName");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("added-by-x509-same-name")}}),
    Status::BadUserAccessDenied)
    << "a UserName rule names a UserName token; a certificate whose common name equals the login is "
       "a different principal and holds none of the rule's Roles";
  EXPECT_EQ(
    count_username_rules(*roleConfiguration, NodeId{0, operatorRoleId}, "added-by-x509-same-name"), 0u);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-AUTHZ-018-USERNAME-CRITERION-BINDS-THE-TOKEN-KIND, scope=function)  // control arm
TEST_F(RbacUserNameRuleSameNameUserNameFixture, TheUserNameIdentityTheRuleNamesHoldsTheRole)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "UserNameSameName");
  EXPECT_EQ(call_status(session,
              NodeId{0, operatorRoleId},
              NodeId{0, operatorAddIdentityMethod},
              {Variant{username_rule("added-by-username-operator")}}),
    Status::Good)
    << "control: the UserName identity the rule names holds SecurityAdmin";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}
