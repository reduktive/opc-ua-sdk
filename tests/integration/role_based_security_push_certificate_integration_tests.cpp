// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// CTT-mirror integration tests for the Push-Certificate-Management x RBAC
/// intersection (Part 18 Role-Based Security x Part 12 Push Model):
///   * SVR-PULLCRT-006 - UpdateCertificate shall require the SecurityAdmin Role.
///   * SVR-PULLCRT-021 - GetRejectedList shall require the SecurityAdmin Role.
///
/// Why this file exists. The push functional suite
/// (`push_certificate_management_tests.cpp`) proves the *channel floor*
/// (`*_NoneChannel_Fails` -> Bad_SecurityModeInsufficient), but its fixture does
/// not provide the Role control pair. The RBAC suites otherwise exercise RoleSet
/// and Role-property nodes, not the push Method nodes. This file binds the
/// SecurityAdmin gate to the actual push Method instance nodes the SDK ships from
/// the UA-1.05.06 NodeSet:
///   * UpdateCertificate  i=13737  AccessRestrictions=3 (Sign+Encrypt),
///     RolePermissions -> SecurityAdmin (i=15704) only.
///   * GetRejectedList    i=12777  AccessRestrictions=1 (Signing),
///     RolePermissions -> SecurityAdmin (i=15704) only.
/// The Call service asks the owning Namespace for the resolved Method node's
/// effective `Call` permission before object/argument validation, so the denial
/// is the Role gate, not argument shape.
///
/// Falsifiability. A node with SecurityAdmin-only RolePermissions fails closed:
/// a negative-only test would also pass against a deny-everyone bug. Each gate
/// therefore pins BOTH a non-admin denial (Bad_UserAccessDenied) AND an admin
/// call that clears the Role gate (!= Bad_UserAccessDenied) over a channel that
/// already satisfies the floor - isolating the Role gate from the channel floor.
///
/// Admin sessions authenticate as the UserName "admin", mapped to the well-known
/// SecurityAdmin Role by `grant_security_admin_to_user`. Non-admin sessions are
/// plain Anonymous (only the Anonymous Role); SecurityAdmin is never granted to
/// an Anonymous session.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/role_based_security_fixture.h"

#include "matchers.h"
#include "requests.h"

#include "ua_attribute_id.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_claim_keys.h"
#include "ua_data_value.h"
#include "ua_method_id.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_session_attribute_services.h"
#include "ua_session_method_services.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variable_id.h"
#include "ua_well_known_role_permissions.h"

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

const NodeId serverConfigObject{ObjectId::ServerConfiguration};

/// Call a Method over the wire and return the per-operation StatusCode (or the
/// service-level result if the request itself failed / returned no results).
StatusCode call_status(
  Session& session, const NodeId& objectId, const NodeId& methodId, std::initializer_list<Variant> args)
{
  auto resp = session.methods().call_sync(call_method(objectId, methodId, args));
  if (!resp.response_header().service_result().is_good())
    return resp.response_header().service_result();
  if (resp.results().empty())
    return StatusCode{Status::BadInternalError};
  return resp.results()[0].status_code();
}

/// Read a single Node Attribute over the wire and return the per-operation
/// StatusCode (or the service-level result on a request-level failure).
StatusCode read_attribute_status(Session& session, const NodeId& node, AttributeId attr)
{
  auto resp = session.attributes().read_sync(read_value(node, attr));
  if (!resp.response_header().service_result().is_good())
    return resp.response_header().service_result();
  if (resp.results().empty())
    return StatusCode{Status::BadInternalError};
  const auto& dv = resp.results()[0];
  return dv.status().has_value() ? *dv.status() : StatusCode{Status::Good};
}

/// DefaultApplicationGroup's TrustList - a CertificateGroups child (NodeSet
/// i=12642) shipping RolePermissions that grant Browse/Read to SecurityAdmin
/// only, with AccessRestrictions=1 (SigningRequired).
const NodeId defaultGroupTrustList{
  ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList};

// The six UpdateCertificate input arguments are built inline at each call site:
// a `std::initializer_list` must not outlive the full-expression that creates its
// backing array, so it cannot be returned from a helper. They are structurally
// well-formed but content-irrelevant - Call authorization fires before argument
// validation, so the non-admin denial does not depend on the cert; the empty
// certificate is what makes the admin call fail *downstream* of the Role gate.

/// SecurityAdmin session: authenticates as UserName "admin", mapped to the
/// well-known SecurityAdmin Role. Every session opened on this fixture is an
/// administrator.
class PushCertRbacAdminFixture : public ComplianceRoleBasedSecurity
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

/// Non-admin session: default Anonymous authenticator, no admin grant. The
/// connecting session resolves to the Anonymous Role only.
class PushCertRbacNonAdminFixture : public ComplianceRoleBasedSecurity
{};

class ClaimMappedAdministrativeAccessFixture : public ComplianceRoleBasedSecurity
{
protected:
  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::UserName,
      "claim-admin",
      std::unordered_map<std::string, std::string>{
        {ClaimKeys::role, std::string{well_known_role_name(WellKnownRole::SecurityAdmin)}},
        {ClaimKeys::diagnosticsFull, "1"},
      });
  }

  void customize_server_configuration(ServerConfig& serverConfig) override
  {
    serverConfig.enableClaimToRoleMapping = true;
  }
};

class ClaimMappingDisabledByDefaultFixture : public ComplianceRoleBasedSecurity
{
protected:
  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::UserName,
      "unmapped-claim-admin",
      std::unordered_map<std::string, std::string>{
        {ClaimKeys::role, std::string{well_known_role_name(WellKnownRole::SecurityAdmin)}},
        {ClaimKeys::diagnosticsFull, "1"},
      });
  }
};

}  // namespace

// ============================================================================
// SVR-PULLCRT-006 - UpdateCertificate requires the SecurityAdmin Role
// (Part 12 section 7.10.4). UpdateCertificate ships AccessRestrictions=3, so a
// SignAndEncrypt channel clears the floor and the Role gate is the sole denier.
// ============================================================================

// @relation(SVR-PULLCRT-006, scope=function)
TEST_F(PushCertRbacNonAdminFixture, UpdateCertificateNonAdminDeniedByRoleGate)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "PushRbacUpdNonAdmin");
  EXPECT_EQ(call_status(session,
              serverConfigObject,
              NodeId{MethodId::ServerConfiguration_UpdateCertificate},
              {Variant{NodeId{}},
                Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::RsaSha256ApplicationCertificateType)}},
                Variant{ByteString{}},
                Variant{Array<ByteString>{}},
                Variant{String{}},
                Variant{ByteString{}}}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(PushCertRbacAdminFixture, UpdateCertificateAdminClearsRoleGate)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "PushRbacUpdAdmin");
  const StatusCode status = call_status(session,
    serverConfigObject,
    NodeId{MethodId::ServerConfiguration_UpdateCertificate},
    {Variant{NodeId{}},
      Variant{NodeId{0, static_cast<uint32_t>(ObjectTypeId::RsaSha256ApplicationCertificateType)}},
      Variant{ByteString{}},
      Variant{Array<ByteString>{}},
      Variant{String{}},
      Variant{ByteString{}}});
  // SecurityAdmin clears the Call Role gate; the empty certificate then fails
  // downstream - the denial above is therefore the Role gate, not the floor.
  EXPECT_NE(status, Status::BadUserAccessDenied)
    << "SecurityAdmin must clear the UpdateCertificate Call Role gate; got " << status.value();
  EXPECT_NE(status, Status::BadSecurityModeInsufficient)
    << "SignAndEncrypt satisfies the UpdateCertificate channel floor; got " << status.value();
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SVR-PULLCRT-021 - GetRejectedList requires the SecurityAdmin Role
// (Part 12 section 7.10.9). GetRejectedList ships AccessRestrictions=1, so a Sign
// channel clears the floor and the Role gate is the sole denier.
// ============================================================================

// @relation(SVR-PULLCRT-021, scope=function)
TEST_F(PushCertRbacNonAdminFixture, GetRejectedListNonAdminDeniedByRoleGate)
{
  auto [channel, session] = open_session(MessageSecurityMode::Sign, "PushRbacGrlNonAdmin");
  EXPECT_EQ(
    call_status(session, serverConfigObject, NodeId{MethodId::ServerConfiguration_GetRejectedList}, {}),
    Status::BadUserAccessDenied);
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(PushCertRbacAdminFixture, GetRejectedListAdminClearsRoleGate)
{
  auto [channel, session] = open_session(MessageSecurityMode::Sign, "PushRbacGrlAdmin");
  const StatusCode status =
    call_status(session, serverConfigObject, NodeId{MethodId::ServerConfiguration_GetRejectedList}, {});
  // SecurityAdmin over a signed channel clears both the floor and the Role gate;
  // GetRejectedList then returns the (empty) rejected list -> Good.
  EXPECT_NE(status, Status::BadUserAccessDenied)
    << "SecurityAdmin must clear the GetRejectedList Call Role gate; got " << status.value();
  EXPECT_NE(status, Status::BadSecurityModeInsufficient)
    << "Sign satisfies the GetRejectedList channel floor; got " << status.value();
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-AUTHZ-025-CLAIM-PATH-ADMINISTERS-NS0, scope=function)
TEST_F(ClaimMappedAdministrativeAccessFixture, ClaimAloneReachesTheAdministrativeSurface)
{
  auto [channel, session] =
    open_session(MessageSecurityMode::SignAndEncrypt, "ClaimMappedAdministrativeAccess");

  EXPECT_EQ(
    call_status(session, serverConfigObject, NodeId{MethodId::ServerConfiguration_GetRejectedList}, {}),
    Status::Good);
  EXPECT_EQ(
    read_attribute_status(session,
      NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray},
      AttributeId::Value),
    Status::Good);

  auto customConfiguration = session.attributes().read_sync(
    read_value(NodeId{VariableId::WellKnownRole_SecurityAdmin_CustomConfiguration}));
  ASSERT_TRUE(customConfiguration.response_header().service_result().is_good());
  ASSERT_EQ(customConfiguration.results().size(), 1u);
  ASSERT_TRUE(customConfiguration.results()[0].status().value_or(StatusCode{Status::Good}).is_good());
  const auto* enabled = customConfiguration.results()[0].value().try_as<bool>();
  ASSERT_NE(enabled, nullptr);
  EXPECT_TRUE(*enabled);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// @relation(AC-SVR-AUTHZ-025-CLAIM-PATH-ADMINISTERS-NS0, scope=function)
TEST_F(ClaimMappingDisabledByDefaultFixture, SameClaimIsInertByDefault)
{
  auto [channel, session] =
    open_session(MessageSecurityMode::SignAndEncrypt, "ClaimMappingDisabledByDefault");

  EXPECT_EQ(
    call_status(session, serverConfigObject, NodeId{MethodId::ServerConfiguration_GetRejectedList}, {}),
    Status::BadUserAccessDenied);
  EXPECT_EQ(
    read_attribute_status(session,
      NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray},
      AttributeId::Value),
    Status::BadUserAccessDenied);

  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

// ============================================================================
// SVR-PULLCRT-002 - CertificateGroups children visible only to SecurityAdmin
// (Part 12 section 7.10.2, demoted SHOULD). The SHALL half (ServerConfiguration +
// immediate children browsable by any Server-Object user) is covered by
// push_certificate_management_tests.cpp:Mirror_ServerConfigurationImmediateChildrenBrowsable.
// Here: a CertificateGroups child (the DefaultApplicationGroup TrustList) ships
// SecurityAdmin-only RolePermissions, so its non-Value Attributes - gated by the
// Browse permission (Part 3 section 8.55 Table 37) - are unreadable by a non-admin and
// readable by SecurityAdmin, over a signed channel that satisfies the floor.
// ============================================================================

// @relation(SVR-PULLCRT-002, scope=function)
TEST_F(PushCertRbacNonAdminFixture, CertificateGroupsChildNotVisibleToNonAdmin)
{
  auto [channel, session] = open_session(MessageSecurityMode::Sign, "PushRbacTrustListNonAdmin");
  EXPECT_EQ(read_attribute_status(session, defaultGroupTrustList, AttributeId::DisplayName),
    Status::BadUserAccessDenied)
    << "A non-admin must not see CertificateGroups children (Browse permission denied)";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}

TEST_F(PushCertRbacAdminFixture, CertificateGroupsChildVisibleToAdmin)
{
  auto [channel, session] = open_session(MessageSecurityMode::Sign, "PushRbacTrustListAdmin");
  EXPECT_EQ(read_attribute_status(session, defaultGroupTrustList, AttributeId::DisplayName), Status::Good)
    << "SecurityAdmin must see CertificateGroups children";
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
}
