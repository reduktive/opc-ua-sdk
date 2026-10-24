// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// CTT-mirror integration tests for the Step 6 / Phase P1 predicate-engine
/// hardening cluster (Part 18 Role-Based Security).
///
/// Each test pairs with a unit test under
/// `tests/unit/server/security/` and a "present (integration, CTT-mirror)"
/// requirements-catalog row. The unit suite exercises the SDK-internal predicate engine in
/// isolation; the integration suite stands up a full Part-18-wired server
/// + a real Client and asserts the role-grant decision over the wire by
/// reading a Variable whose `RolePermissions` are restricted to the
/// custom role under test - Read returns `Good` iff the role was granted,
/// `BadUserAccessDenied` otherwise. This is the canonical wire-side
/// observable for role grants given the SDK does not (yet) expose a
/// `GrantedRoleIds` Attribute at the Session level.
///
/// Coverage map (SECADMIN-029, 031, 032, 033, 059 - all P1-closed):
///   * `ApplicationsFilterSignedChannelFloor` - SECADMIN-029
///   * `ThumbprintCriteriaFormat`             - SECADMIN-031
///   * `ApplicationCriteriaGate`              - SECADMIN-032
///   * `X509SubjectCriteriaFormat`            - SECADMIN-033
///   * `AnonymousRoleDefaultIdentities`       - SECADMIN-059
///
/// The `*IdentitiesWireFixture` tests additionally read a Role's `Identities`
/// Property over the wire and assert the decoded `Array<IdentityMappingRule
/// Type>` payload (canonical Thumbprint / X509Subject form + the Anonymous
/// dual-rule). The reader holds `SecurityAdmin` (UA-1.05.06 grants Read on the
/// Role `Identities` Variables to SecurityAdmin only) and uses SignAndEncrypt
/// because the RoleSet surface is admin-gated + `EncryptionRequired`.
///
/// All tests use the `ComplianceRoleBasedSecurity` fixture
/// (`helpers/role_based_security_fixture.h`) which extends
/// `ComplianceSecured` with Part-18 wiring + per-test RoleConfiguration
/// customisation + per-test address-space customisation.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "helpers/role_based_security_fixture.h"

#include "matchers.h"
#include "requests.h"

#include "ua_crypto_types.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_status.h"
#include "ua_variable_id.h"

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

/// Custom Role + Variable numeric ids - fixture captures the actual
/// namespace index assigned by `install_test_namespace` and uses it to
/// construct concrete NodeIds.
constexpr uint32_t appsFilterRoleNumericId{50001};
constexpr uint32_t appCriteriaRoleNumericId{50002};
constexpr uint32_t thumbprintRoleNumericId{50003};
constexpr uint32_t x509SubjectRoleNumericId{50004};
constexpr uint32_t trustedAppRoleNumericId{50005};

constexpr uint32_t appsFilterTestVarId{60001};
constexpr uint32_t appCriteriaTestVarId{60002};
constexpr uint32_t thumbprintTestVarId{60003};
constexpr uint32_t x509SubjectTestVarId{60004};
constexpr uint32_t trustedAppTestVarId{60006};
constexpr uint32_t anonymousDualRuleVarId{60005};

IdentityMappingRuleType make_rule(IdentityCriteriaType type, std::string criteria = {})
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = type;
  rule.criteria() = String{std::move(criteria)};
  return rule;
}

/// Grant the `SecurityAdmin` Role to any Anonymous session. The UA-1.05.06
/// NodeSet restricts each Role's child `Identities` Variable Value to the
/// `SecurityAdmin` Role (RolePermissions grant Read only to SecurityAdmin), so
/// a reader that wants to inspect a Role's `Identities` Value over the wire must
/// hold SecurityAdmin. Pre-populating the `SecurityAdmin` slot (canonical bit 7)
/// makes `seed_well_known_roles` leave it alone.
void grant_security_admin_to_anonymous(ua::server::RoleConfiguration& config)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)};
  def.roleBit = 7;
  ASSERT_TRUE(config.add_role(std::move(def)));
  auto result =
    config.add_identity_rule(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_SecurityAdmin)},
      make_rule(IdentityCriteriaType::Anonymous));
  ASSERT_TRUE(result.is_good()) << "SecurityAdmin Anonymous rule must register: "
                                << result.status_code().value();
}

/// Try to Read the Variable's Value attribute on the given mode. Returns
/// the StatusCode of the first per-operation result (or the service
/// result if no per-op result was returned).
StatusCode read_value_status(ComplianceRoleBasedSecurity& fixture, MessageSecurityMode mode,
  const NodeId& variableId, const std::string& sessionName)
{
  auto [channel, session] = fixture.open_session(mode, sessionName);
  auto resp = session.attributes().read_sync(read_value(variableId));
  StatusCode status{Status::Good};
  if (!resp.response_header().service_result().is_good())
  {
    status = resp.response_header().service_result();
  }
  else if (resp.results().empty())
  {
    status = StatusCode{Status::BadInternalError};
  }
  else
  {
    const auto& dv = resp.results()[0];
    status = dv.status().value_or(StatusCode{Status::Good});
  }
  (void)session.try_close_sync();
  (void)channel.try_close_sync();
  return status;
}

}  // namespace

// ============================================================================
// SECADMIN-029 - Applications-filtered Role signed-channel floor (Part 18
// section 4.4.1 L665-671)
// ============================================================================

/// Configures a Role whose `applications` list contains the test client's
/// cert URI and whose identity rule grants the role to any Anonymous
/// session. Creates a Variable whose `RolePermissions` grant Read+Browse
/// to that custom Role only. Verifies that:
///   * None-mode Session: Apps-filter floor rejects, role not granted,
///     Read returns `BadUserAccessDenied`.
///   * Sign-mode Session: floor clears (channel is signed), URI matches
///     (auto-populated via the cert's SAN URI claim, Phase P1 producer),
///     identity rule matches, role granted, Read returns Good.
///   * SignAndEncrypt-mode Session: same as Sign.
class ApplicationsFilterFloorFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    // Use NS=1 conventionally for the role; the actual namespace index
    // for the test variable is captured at customize_address_space time.
    mCustomRole = NodeId{1, appsFilterRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 10;
    def.applications = {String{"urn:test:compliance:client"}};
    def.applicationsExclude = false;
    def.identities = {make_rule(IdentityCriteriaType::Anonymous)};
    ASSERT_TRUE(config.add_role(std::move(def)));
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"app:uri", "urn:test:compliance:client"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:apps-filter");
    mTestVariable = NodeId{nsIndex, appsFilterTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "AppsFilterRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

/// Wave I strengthening (configuration coverage matrix section 12): `applicationsExclude` inverts the
/// meaning of `applications` from an include list to an exclude list. Every fixture above sets it to `false`
/// - the field's DEFAULT - so the `true` path, which flips an authorization decision, was exercised only by a
/// unit test. This fixture is `ApplicationsFilterFloorFixture` with that one flag inverted and nothing
/// else changed: the same Role, the same application URI, the same identity rule, the same gated variable.
///
/// The oracle is therefore the inversion itself. Under `false` a Sign-mode read of the gated variable
/// returns Good (SignChannelGrantsReadFloorClears, above); under `true` the same client is EXCLUDED by the
/// same list, so the Role is not granted and the read must be denied. A server that ignored the flag would
/// grant the Role in both fixtures and this test would fail.
class ApplicationsFilterExcludeFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, appsFilterRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 10;
    def.applications = {String{"urn:test:compliance:client"}};
    def.applicationsExclude = true;  // default false - the whole point of this fixture
    def.identities = {make_rule(IdentityCriteriaType::Anonymous)};
    ASSERT_TRUE(config.add_role(std::move(def)));
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"app:uri", "urn:test:compliance:client"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:apps-filter-exclude");
    mTestVariable = NodeId{nsIndex, appsFilterTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "AppsFilterExcludeRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

/// Row: RoleConfiguration::IdentityMappingRule::applicationsExclude.
TEST_F(ApplicationsFilterExcludeFixture, ExcludeModeDeniesTheListedApplication)
{
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::Sign, mTestVariable, "AppsFilterExclude"),
    Status::BadUserAccessDenied)
    << "with applicationsExclude=true the listed application URI must be EXCLUDED from the Role, so the "
       "gated read is denied - the same client, same Role and same Sign-mode channel are granted Good "
       "under the include-mode fixture above";
}

// @relation(AC-SVR-SECADMIN-029-APPLICATIONS-NEEDS-SIGNING, scope=function)
// @relation(AC-SVR-AUTHZ-005-SECURITY-MODE-SPLITS-IDENTITY, scope=function)
TEST_F(ApplicationsFilterFloorFixture, NoneChannelDeniesReadFloorRejects)
{
  // Apps-filter floor (Part 18 section 4.4.1 L665-671): a Role with a non-empty
  // `applications` requires at least a signed channel. None-mode fails
  // the floor, the role is not granted, and the per-Node RolePermissions
  // (granting only the custom role) deny the Read.
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::None, mTestVariable, "AppsFilterNone"),
    Status::BadUserAccessDenied);
}

// @relation(AC-SVR-AUTHZ-005-SECURITY-MODE-SPLITS-IDENTITY, scope=function)
TEST_F(ApplicationsFilterFloorFixture, SignChannelGrantsReadFloorClears)
{
  // Sign mode clears the Apps-filter floor. The test authenticator
  // injected `app:uri` matching the role's `applications` entry;
  // Anonymous-criteria identity rule matches the Anonymous session;
  // role granted; Read succeeds.
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::Sign, mTestVariable, "AppsFilterSign"), Status::Good);
}

TEST_F(ApplicationsFilterFloorFixture, SignAndEncryptChannelGrantsReadFloorClears)
{
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "AppsFilterSignAndEncrypt"),
    Status::Good);
}

// ============================================================================
// SECADMIN-032 - Application criteria trusted-cert + signed-channel gate
// (Part 18 section 4.4.3 L785-788)
// ============================================================================

/// Configures a Role whose only identity rule is `Application` criteria
/// matching the test client's cert URI. The role is granted iff the
/// composite gate clears: (a) channel is at least signed, (b) client
/// cert is trusted, and (c) the cert's SAN URI matches the criteria.
/// Tests verify:
///   * None mode: no client cert is sent, no `client_cert_trusted` claim,
///     gate fails, role denied.
///   * Sign mode: client cert is sent + validated by the trust list at
///     OPN time. The session-side producer auto-sets
///     `client_cert_trusted=true` and `app:uri` claims. Rule matches.
///   * SignAndEncrypt mode: same.
class ApplicationCriteriaGateFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, appCriteriaRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 11;
    def.identities = {make_rule(IdentityCriteriaType::Application, "urn:test:compliance:client")};
    ASSERT_TRUE(config.add_role(std::move(def)));
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"app:uri", "urn:test:compliance:client"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:app-criteria");
    mTestVariable = NodeId{nsIndex, appCriteriaTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "AppCriteriaRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

// @relation(SVR-SECADMIN-032, scope=function)
TEST_F(ApplicationCriteriaGateFixture, NoneChannelDeniesReadGateRejects)
{
  // None mode: no client cert is presented at OPN, so the session-side
  // producer in `ua_server_session.cpp` does NOT set
  // `client_cert_trusted=true`. The rule's signed-channel + trusted-cert
  // gates both fail; role not granted; Read denied by per-Node
  // RolePermissions.
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::None, mTestVariable, "AppCriteriaNone"),
    Status::BadUserAccessDenied);
}

TEST_F(ApplicationCriteriaGateFixture, SignChannelGrantsReadGateClears)
{
  // Sign mode: OPN validated the client cert against the trust list; the
  // session-side producer auto-set `client_cert_trusted=true`. Test
  // authenticator injected `app:uri`. All three gates pass.
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::Sign, mTestVariable, "AppCriteriaSign"), Status::Good);
}

TEST_F(ApplicationCriteriaGateFixture, SignAndEncryptChannelGrantsReadGateClears)
{
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "AppCriteriaSignAndEncrypt"),
    Status::Good);
}

// ============================================================================
// SECADMIN-069 - TrustedApplication criteria trusted-cert + signed-channel gate
// (Part 18 section 4.4.3, 1.05.04+ - IdentityCriteriaType value 9)
// ============================================================================

/// Configures a Role whose only identity rule is the `TrustedApplication`
/// criteria (no ApplicationUri - it matches ANY trusted application). The role
/// is granted iff both gates clear: (a) channel is at least signed, (b) the
/// client cert is trusted. Unlike `Application`, no `app:uri` claim is needed
/// because the criteria does not compare the URI.
///   * None mode: no client cert is sent, no `client_cert_trusted` claim,
///     gate fails, role denied.
///   * Sign / SignAndEncrypt mode: client cert is validated by the trust list
///     at OPN time; the session-side producer auto-sets
///     `client_cert_trusted=true`. Rule matches even with the default
///     (claim-free) anonymous authenticator.
class TrustedApplicationCriteriaGateFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, trustedAppRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 12;
    def.identities = {make_rule(IdentityCriteriaType::TrustedApplication)};
    ASSERT_TRUE(config.add_role(std::move(def)));
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:trusted-app-criteria");
    mTestVariable = NodeId{nsIndex, trustedAppTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "TrustedAppCriteriaRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

TEST_F(TrustedApplicationCriteriaGateFixture, NoneChannelDeniesReadGateRejects)
{
  // None mode: no client cert presented at OPN, so `client_cert_trusted` is
  // never set. The trusted-cert + signed-channel gates fail; role not granted;
  // Read denied by per-Node RolePermissions.
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::None, mTestVariable, "TrustedAppNone"),
    Status::BadUserAccessDenied);
}

TEST_F(TrustedApplicationCriteriaGateFixture, SignChannelGrantsReadGateClears)
{
  // Sign mode: OPN validated the client cert; the session-side producer
  // auto-set `client_cert_trusted=true`. No app:uri needed - both gates pass.
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::Sign, mTestVariable, "TrustedAppSign"), Status::Good);
}

TEST_F(TrustedApplicationCriteriaGateFixture, SignAndEncryptChannelGrantsReadGateClears)
{
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "TrustedAppSignAndEncrypt"),
    Status::Good);
}

// ============================================================================
// SECADMIN-031 - Thumbprint criteria format (Part 18 section 4.4.3 L766-769)
// ============================================================================

/// The wire-level Thumbprint match requires the user-side `thumbprint`
/// claim to canonicalise to the same upper-case-hex-no-spaces form as the
/// stored rule. The SDK does not auto-populate `thumbprint` from X509
/// user identity tokens today; this fixture uses
/// `ClaimInjectingAuthenticator` to inject a non-canonical thumbprint
/// claim, then verifies the matching path canonicalises both sides before
/// comparison.
class ThumbprintCriteriaFormatFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, thumbprintRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 12;
    ASSERT_TRUE(config.add_role(std::move(def)));
    // Configure the rule with a non-canonical input. `add_identity_rule`
    // canonicalises it to "ABCDEF0123" before storage.
    auto result =
      config.add_identity_rule(mCustomRole, make_rule(IdentityCriteriaType::Thumbprint, "ab cd ef 01 23"));
    ASSERT_TRUE(result.is_good()) << "Non-canonical Thumbprint input must be canonicalised cleanly: "
                                  << result.status_code().value();
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    // Inject a non-canonical thumbprint claim. The matching path's
    // user-side normaliser must canonicalise it to "ABCDEF0123" before
    // comparing against the stored rule.
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"thumbprint", "ab-cd-ef-01-23"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:thumbprint");
    mTestVariable = NodeId{nsIndex, thumbprintTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "ThumbprintRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

TEST_F(ThumbprintCriteriaFormatFixture, MatchingNormalisesBothSidesOverTheWire)
{
  // Stored rule configured with "ab cd ef 01 23" -> canonicalised to
  // "ABCDEF0123" at config time. User-side claim "ab-cd-ef-01-23" ->
  // canonicalised to the same form at compare time. Match -> role granted
  // -> Read succeeds. Both sides normalise; format discipline holds
  // end-to-end.
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "ThumbprintMatch"),
    Status::Good);
}

class ThumbprintMismatchFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, thumbprintRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 12;
    ASSERT_TRUE(config.add_role(std::move(def)));
    auto result =
      config.add_identity_rule(mCustomRole, make_rule(IdentityCriteriaType::Thumbprint, "ABCDEF0123"));
    ASSERT_TRUE(result.is_good());
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    // Inject a thumbprint that canonicalises to a DIFFERENT value than
    // the stored rule - proves the matcher is not always-accepting.
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"thumbprint", "deadbeef"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:thumbprint-miss");
    mTestVariable = NodeId{nsIndex, thumbprintTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "ThumbprintRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

TEST_F(ThumbprintMismatchFixture, MismatchedThumbprintDeniesRead)
{
  // Falsifiability gate: confirms the matcher rejects when canonical
  // forms differ. Without this, the positive test above could be passing
  // because the matcher is unconditional.
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "ThumbprintMiss"),
    Status::BadUserAccessDenied);
}

// ============================================================================
// SECADMIN-033 - X509Subject criteria canonicalisation (Part 18 section 4.4.3
// L793-808 + Table 8)
// ============================================================================

/// Configures the rule with an out-of-order X509Subject input (canonicaliser
/// reorders it at config time) and injects a similarly out-of-order user-
/// side `x509:subject` claim (canonicalised at compare time). If both sides
/// canonicalise consistently, they match and the role is granted.
class X509SubjectCriteriaFormatFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, x509SubjectRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 13;
    ASSERT_TRUE(config.add_role(std::move(def)));
    auto result = config.add_identity_rule(mCustomRole,
      make_rule(IdentityCriteriaType::X509Subject, R"(O="Acme"/CN="Alice"/L="Berlin"/OU="Eng")"));
    ASSERT_TRUE(result.is_good()) << "Out-of-order X509Subject must canonicalise: "
                                  << result.status_code().value();
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{
        {"x509:subject", R"(L="Berlin"/OU="Eng"/CN="Alice"/O="Acme")"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:x509subject");
    mTestVariable = NodeId{nsIndex, x509SubjectTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "X509SubjectRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

TEST_F(X509SubjectCriteriaFormatFixture, CanonicalFormMatchesOverTheWire)
{
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "X509SubjectMatch"),
    Status::Good);
}

class X509SubjectMismatchFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, x509SubjectRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 13;
    ASSERT_TRUE(config.add_role(std::move(def)));
    auto result = config.add_identity_rule(
      mCustomRole, make_rule(IdentityCriteriaType::X509Subject, R"(CN="Alice"/O="Acme")"));
    ASSERT_TRUE(result.is_good());
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"x509:subject", R"(CN="Bob"/O="DifferentOrg")"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:x509subject-miss");
    mTestVariable = NodeId{nsIndex, x509SubjectTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "X509SubjectRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

TEST_F(X509SubjectMismatchFixture, MismatchedSubjectDeniesRead)
{
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "X509SubjectMiss"),
    Status::BadUserAccessDenied);
}

// ============================================================================
// SECADMIN-059 - Anonymous Role default `Identities` dual-rule (Part 18
// section 4.3 L408-414)
// ============================================================================

/// The dual-rule semantics: the Anonymous Role grants Read on a Variable
/// whose `RolePermissions` allow only the Anonymous Role to BOTH (a) an
/// Anonymous-token-kind session AND (b) a non-Anonymous-token-kind
/// (authenticated) session. Both halves are tested:
///   * `AnonymousSessionGrantedAnonymousRole` - Anonymous-token session.
///   * `AuthenticatedSessionAlsoGrantedAnonymousRole` - the dual-rule
///     half: authenticated session (non-Anonymous user kind) STILL gets
///     the Anonymous Role because of the `AuthenticatedUser` rule on the
///     Anonymous Role. Without the dual-rule, this test would fail.
class AnonymousDualRuleFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;

  void customize_role_configuration(RoleConfiguration& /*config*/) override
  {
    // No customisation - rely on `seed_well_known_roles` to install the
    // Anonymous Role with the dual rule (Anonymous + AuthenticatedUser).
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:anon-dual");
    mTestVariable = NodeId{nsIndex, anonymousDualRuleVarId};
    // RolePermissions grant Read+Browse only to the Anonymous Role
    // (NS0 NodeId 15644 / WellKnownRole_Anonymous).
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "AnonymousDualRuleInt32",
      {make_role_permission(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous)},
        {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

TEST_F(AnonymousDualRuleFixture, AnonymousSessionGrantedAnonymousRole)
{
  // Baseline: an Anonymous-token session matches the `Anonymous`-criteria
  // rule on the Anonymous Role. Role granted. Read succeeds.
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "AnonAnonymous"),
    Status::Good);
}

class AnonymousDualRuleAuthenticatedFixture : public AnonymousDualRuleFixture
{
protected:
  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    // Inject a non-Anonymous user-kind (UserName) so the
    // `AuthenticatedUser` criteria half of the dual-rule fires. The
    // Anonymous Role's `Anonymous` criteria would NOT match this
    // session; only the dual-rule's `AuthenticatedUser` criteria does.
    return std::make_shared<ClaimInjectingAuthenticator>(
      UserTokenKind::UserName, /*userId=*/"alice", std::unordered_map<std::string, std::string>{});
  }
};

TEST_F(AnonymousDualRuleAuthenticatedFixture, AuthenticatedSessionAlsoGrantedAnonymousRole)
{
  // Dual-rule pin (SECADMIN-059): an authenticated session
  // (UserName user-kind) gets the Anonymous Role granted via the
  // `AuthenticatedUser` criteria half. Without the dual-rule -
  // i.e. if `seed_well_known_roles` shipped only the `Anonymous`
  // criteria as the SDK did before P1 - this test would fail (role not
  // granted, Read returns `BadUserAccessDenied`).
  EXPECT_EQ(read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "AnonAuthenticated"),
    Status::Good);
}

// ============================================================================
// Wire-side payload inspection of Role `Identities` Properties.
//
// The grant-decision tests above pin role grants via Read status; these
// complementary tests read the populated `Array<IdentityMappingRuleType>`
// Value of a Role's `Identities` Property over the wire and assert its
// *decoded content* - the stored canonical / dual-rule form. This exercises
// the structure-array Variant encode->decode round-trip end-to-end (the path
// previously broken by the `decode_array_variant` ExtensionObject stub, which
// hung populated reads). All reads use a SignAndEncrypt session because the
// RoleSet surface carries an `EncryptionRequired` AccessRestriction.
// ============================================================================

// SECADMIN-059 - the Anonymous Role's default `Identities` array, observed
// over the wire, carries BOTH the `Anonymous` and `AuthenticatedUser` rules
// (Part 18 section 4.3 L408-414). This is the wire-side complement to the
// grant-decision dual-rule pins above. The reading session is granted
// `ConfigureAdmin` so it can read the admin-gated RoleSet surface; the
// Anonymous Role itself is left to `seed_well_known_roles` so its default
// dual-rule is the thing under test.
class AnonymousIdentitiesWireFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_anonymous(config);
  }
};

// @relation(SVR-SECADMIN-059, scope=function)
TEST_F(AnonymousIdentitiesWireFixture, AnonymousRoleDefaultIdentities)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "AnonIdentitiesRead");
  auto rules = read_role_identities(
    session, NodeId{0, static_cast<uint32_t>(VariableId::WellKnownRole_Anonymous_Identities)});
  (void)session.try_close_sync();
  (void)channel.try_close_sync();

  ASSERT_EQ(rules.size(), 2u) << "Anonymous Role ships with the Anonymous + AuthenticatedUser dual rule.";
  EXPECT_EQ(rules[0].criteria_type(), IdentityCriteriaType::Anonymous);
  EXPECT_EQ(rules[1].criteria_type(), IdentityCriteriaType::AuthenticatedUser);
}

// SECADMIN-031 - Thumbprint criteria are stored in upper-case-hex,
// separator-free canonical form (Part 18 section 4.4.2). Configure a (spare)
// well-known Role with a deliberately non-canonical Thumbprint input and
// confirm the canonical form "ABCDEF0123" is what is served over the wire.
class ThumbprintIdentitiesWireFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_anonymous(config);
    // Pre-populate the Observer slot (canonical bit 2) so
    // `seed_well_known_roles` leaves it alone and `populate_role_set`
    // mirrors our rule into `WellKnownRole_Observer.Identities`.
    RoleConfiguration::RoleDefinition def;
    def.roleId = NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Observer)};
    def.roleBit = 2;
    ASSERT_TRUE(config.add_role(std::move(def)));
    auto result = config.add_identity_rule(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Observer)},
      make_rule(IdentityCriteriaType::Thumbprint, "ab cd ef 01 23"));
    ASSERT_TRUE(result.is_good()) << "Non-canonical Thumbprint input must canonicalise cleanly: "
                                  << result.status_code().value();
  }
};

// @relation(SVR-SECADMIN-031, scope=function)
TEST_F(ThumbprintIdentitiesWireFixture, ThumbprintCriteriaFormat)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "ThumbprintIdentitiesRead");
  auto rules = read_role_identities(
    session, NodeId{0, static_cast<uint32_t>(VariableId::WellKnownRole_Observer_Identities)});
  (void)session.try_close_sync();
  (void)channel.try_close_sync();

  ASSERT_EQ(rules.size(), 1u);
  EXPECT_EQ(rules[0].criteria_type(), IdentityCriteriaType::Thumbprint);
  EXPECT_EQ(rules[0].criteria(), String{"ABCDEF0123"})
    << "Stored Thumbprint criteria must be served in upper-case-hex, separator-free canonical form.";
}

// SECADMIN-033 - X509Subject criteria are stored in Table-8-ordered token
// form (Part 18 section 4.4.3 L793-808 + Table 8). Configure a (spare) well-known
// Role with an out-of-order X509Subject input and confirm the Table-8
// canonical ordering is what is served over the wire.
class X509SubjectIdentitiesWireFixture : public ComplianceRoleBasedSecurity
{
protected:
  void customize_role_configuration(RoleConfiguration& config) override
  {
    grant_security_admin_to_anonymous(config);
    // Pre-populate the Operator slot (canonical bit 3).
    RoleConfiguration::RoleDefinition def;
    def.roleId = NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Operator)};
    def.roleBit = 3;
    ASSERT_TRUE(config.add_role(std::move(def)));
    auto result = config.add_identity_rule(NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Operator)},
      make_rule(IdentityCriteriaType::X509Subject, R"(O="Acme"/CN="Alice"/L="Berlin"/OU="Eng")"));
    ASSERT_TRUE(result.is_good()) << "Out-of-order X509Subject must canonicalise: "
                                  << result.status_code().value();
  }
};

// @relation(SVR-SECADMIN-033, scope=function)
TEST_F(X509SubjectIdentitiesWireFixture, X509SubjectCriteriaFormat)
{
  auto [channel, session] = open_session(MessageSecurityMode::SignAndEncrypt, "X509SubjectIdentitiesRead");
  auto rules = read_role_identities(
    session, NodeId{0, static_cast<uint32_t>(VariableId::WellKnownRole_Operator_Identities)});
  (void)session.try_close_sync();
  (void)channel.try_close_sync();

  ASSERT_EQ(rules.size(), 1u);
  EXPECT_EQ(rules[0].criteria_type(), IdentityCriteriaType::X509Subject);
  EXPECT_EQ(rules[0].criteria(), String{R"(CN="Alice"/O="Acme"/OU="Eng"/L="Berlin")"})
    << "Stored X509Subject criteria must be served in Table-8 canonical order.";
}

// ============================================================================
// Rule-creation format discipline + the fused Application-criteria gate.
//
// The `*IdentitiesWireFixture` tests above observe what the server *emits*
// once a rule is stored. The tests below observe the complementary half: what
// the server *accepts* when the rule is created, and what the Application
// criteria requires before it contributes a Role grant.
// ============================================================================

namespace
{

/// Scratch (server-free) `RoleConfiguration` carrying one registered Role, so
/// rule-creation outcomes are attributable to the criteria string alone and
/// not to an unknown Role id. The Role id / bit are private to the scratch
/// instance and never reach a server.
constexpr uint32_t scratchRoleNumericId{50090};
constexpr uint8_t scratchRoleBit{20};

NodeId register_scratch_role(RoleConfiguration& scratch)
{
  const NodeId roleId{1, scratchRoleNumericId};
  RoleConfiguration::RoleDefinition def;
  def.roleId = roleId;
  def.roleBit = scratchRoleBit;
  EXPECT_TRUE(scratch.add_role(std::move(def))) << "scratch Role must register";
  return roleId;
}

}  // namespace

/// A Role whose sole identity rule is a Thumbprint criteria already in the
/// spec-prescribed form (upper-case hexadecimal, no separators), paired with a
/// session presenting a certificate whose thumbprint is that same value. This
/// is the "correctly-formed rule matches the certificate" half of the
/// obligation; the malformed-input half is exercised against a scratch
/// `RoleConfiguration` inside the test body so a rejected rule never has to be
/// installed into a running server.
class ThumbprintCanonicalFormFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, thumbprintRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 14;
    ASSERT_TRUE(config.add_role(std::move(def)));
    auto result =
      config.add_identity_rule(mCustomRole, make_rule(IdentityCriteriaType::Thumbprint, "ABCDEF0123"));
    ASSERT_TRUE(result.is_good()) << "Canonical Thumbprint criteria must be accepted: "
                                  << result.status_code().value();
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    // The certificate presented by the session, expressed as the thumbprint
    // claim the SDK's predicate engine consumes (the SDK does not yet derive
    // this claim from an X509 user token - see the fixture header).
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"thumbprint", "ABCDEF0123"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:thumbprint-canonical");
    mTestVariable = NodeId{nsIndex, thumbprintTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "ThumbprintCanonicalRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

// Part 18 section 4.4.3 L766-769: "the thumbprint shall be encoded as a hexadecimal
// string with upper case characters and without spaces." Every common tool
// prints thumbprints in a form that clause forbids - openssl lower-cases and
// inserts colons, certificate viewers group bytes with spaces - so a plausible
// implementation tolerates those inputs and silently rewrites them. That is
// exactly the failure mode this criterion forbids: the malformed forms must be
// refused while the administrator still has the thumbprint in front of them,
// and only the spec-form rule may be stored and matched.
// @verifies AC-SVR-SECADMIN-031-THUMBPRINT-FORM
TEST_F(ThumbprintCanonicalFormFixture, MalformedThumbprintCriteriaRefusedAtRuleCreation)
{
  RoleConfiguration scratch;
  const NodeId scratchRole = register_scratch_role(scratch);

  // Control: the spec form is accepted. Asserted first so a refusal below can
  // never be a vacuous consequence of an unregistered Role or a rejecting
  // entry point.
  ASSERT_TRUE(
    scratch.add_identity_rule(scratchRole, make_rule(IdentityCriteriaType::Thumbprint, "ABCDEF0123"))
      .is_good())
    << "the upper-case, separator-free spec form must be accepted";

  EXPECT_TRUE(
    scratch.add_identity_rule(scratchRole, make_rule(IdentityCriteriaType::Thumbprint, "abcdef0123"))
      .is_bad())
    << "lower-case hexadecimal is not the Part 18 section 4.4.3 form and must be refused at rule creation";
  EXPECT_TRUE(
    scratch.add_identity_rule(scratchRole, make_rule(IdentityCriteriaType::Thumbprint, "AB:CD:EF:01:23"))
      .is_bad())
    << "colon-separated hexadecimal (openssl output) must be refused at rule creation";
  EXPECT_TRUE(
    scratch.add_identity_rule(scratchRole, make_rule(IdentityCriteriaType::Thumbprint, "AB CD EF 01 23"))
      .is_bad())
    << "space-separated hexadecimal (certificate-viewer output) must be refused at rule creation";

  // Second conjunct: the correctly-formed rule installed by the fixture
  // matches the certificate presented by the session, so the Role is granted
  // and the Role-gated Read succeeds.
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "ThumbprintCanonicalMatch"),
    Status::Good)
    << "a Thumbprint rule in the spec form must match a certificate whose thumbprint is that value";
}

/// A Role whose sole identity rule is an X509Subject criteria already in the
/// Table 8 grammar - `/`-separated `Name="Value"` tokens, Table-8 names only,
/// lowest-numbered name first - paired with a session presenting that same
/// subject. Nothing malformed is ever installed into this server; the
/// malformed inputs are offered to a scratch `RoleConfiguration` in the test
/// body.
class X509SubjectGrammarFixture : public ComplianceRoleBasedSecurity
{
protected:
  NodeId mTestVariable;
  NodeId mCustomRole;

  void customize_role_configuration(RoleConfiguration& config) override
  {
    mCustomRole = NodeId{1, x509SubjectRoleNumericId};
    RoleConfiguration::RoleDefinition def;
    def.roleId = mCustomRole;
    def.roleBit = 15;
    ASSERT_TRUE(config.add_role(std::move(def)));
    auto result = config.add_identity_rule(
      mCustomRole, make_rule(IdentityCriteriaType::X509Subject, R"(CN="Alice"/O="Acme")"));
    ASSERT_TRUE(result.is_good()) << "Table-8-ordered X509Subject criteria must be accepted: "
                                  << result.status_code().value();
  }

  std::shared_ptr<UserAuthenticator> make_authenticator() override
  {
    return std::make_shared<ClaimInjectingAuthenticator>(UserTokenKind::Anonymous,
      /*userId=*/"",
      std::unordered_map<std::string, std::string>{{"x509:subject", R"(CN="Alice"/O="Acme")"}});
  }

  void customize_address_space(AddressSpace& addressSpace) override
  {
    const auto nsIndex = install_test_namespace(addressSpace, "urn:test:rbac:x509subject-grammar");
    mTestVariable = NodeId{nsIndex, x509SubjectTestVarId};
    create_role_gated_variable(addressSpace,
      mTestVariable,
      "X509SubjectGrammarRoleGatedInt32",
      {make_role_permission(mCustomRole, {PermissionType::Bit::Browse, PermissionType::Bit::Read})});
  }
};

// Part 18 section 4.4.3 L793-808 + Table 8: the criteria "consists of a sequence of
// name value pairs separated by a '/'", each name drawn from Table 8, each
// value in double quotes, the pairs in Table-8 order. A plausible
// implementation parses leniently - dropping names it does not recognise,
// re-sorting whatever order it is given - and stores a string the
// administrator did not write. Both directions are silent authorisation
// failures: a dropped attribute widens the rule to certificates it was never
// meant to cover, and neither is visible at the moment the rule is added,
// which is why the rejection belongs at that moment.
// @verifies AC-SVR-SECADMIN-033-X509SUBJECT-FORMAT
TEST_F(X509SubjectGrammarFixture, MalformedX509SubjectCriteriaRefusedAtRuleCreation)
{
  RoleConfiguration scratch;
  const NodeId scratchRole = register_scratch_role(scratch);

  // Control: a grammar-conforming, Table-8-ordered criteria is accepted.
  // Asserted first so the refusals below cannot pass vacuously.
  ASSERT_TRUE(
    scratch
      .add_identity_rule(scratchRole, make_rule(IdentityCriteriaType::X509Subject, R"(CN="Alice"/O="Acme")"))
      .is_good())
    << "a Table-8-ordered, fully quoted criteria must be accepted";

  EXPECT_TRUE(scratch
                .add_identity_rule(scratchRole,
                  make_rule(IdentityCriteriaType::X509Subject, R"(CN="Alice"/EMAIL="alice@acme.example")"))
                .is_bad())
    << "an attribute name outside Table 8 must be refused, not silently dropped - dropping it stores a "
       "broader rule than the administrator wrote";
  EXPECT_TRUE(
    scratch.add_identity_rule(scratchRole, make_rule(IdentityCriteriaType::X509Subject, R"(CN=Alice)"))
      .is_bad())
    << "an unquoted value must be refused (Part 18 section 4.4.3 L796: the value is always enclosed in "
       "double quotes)";
  EXPECT_TRUE(
    scratch
      .add_identity_rule(scratchRole, make_rule(IdentityCriteriaType::X509Subject, R"(CN="Alice"O="Acme")"))
      .is_bad())
    << "a missing '/' separator must be refused (Part 18 section 4.4.3 L795)";
  EXPECT_TRUE(
    scratch
      .add_identity_rule(scratchRole, make_rule(IdentityCriteriaType::X509Subject, R"(O="Acme"/CN="Alice")"))
      .is_bad())
    << "attributes out of Table-8 order must be refused, not re-sorted (Part 18 section 4.4.3 L797: the "
       "order shall be by the order shown in Table 8 with the lowest number first)";

  // The accepted, grammar-conforming rule the fixture installed still matches
  // end-to-end, so refusal at creation is not achieved by refusing everything.
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::SignAndEncrypt, mTestVariable, "X509SubjectGrammarMatch"),
    Status::Good)
    << "a grammar-conforming X509Subject rule must still grant the Role";
}

// Part 18 section 4.4.3 L785-788: for the `Application` criteriaType "the Client
// Certificate shall be trusted by the Server AND the Session shall use at
// least a signed communication channel." A plausible implementation derives
// the trust verdict from the channel - "the channel is open and signed and a
// certificate was presented, therefore the certificate is trusted" - which
// collapses the conjunction into its second conjunct alone. Testing each
// condition failing on its own is what distinguishes the conjunction from
// either half.
// @verifies AC-SVR-SECADMIN-032-APPLICATION-CRITERIA
TEST_F(ApplicationCriteriaGateFixture, ApplicationCriteriaNeedsTrustedCertificateAndSignedChannelTogether)
{
  // Control: with both conditions met the Role IS granted, so the two denials
  // below are attributable to the condition each removes and not to a
  // permanently closed gate.
  ASSERT_EQ(
    read_value_status(*this, MessageSecurityMode::Sign, mTestVariable, "AppCriteriaBothConditionsHold"),
    Status::Good)
    << "trusted certificate + signed channel must grant the Role";

  // Conjunct 2 failing alone: the fixture's client certificate is on the
  // server's trust list, but a None-mode channel is not a signed channel.
  EXPECT_EQ(
    read_value_status(*this, MessageSecurityMode::None, mTestVariable, "AppCriteriaTrustedCertNoneChannel"),
    Status::BadUserAccessDenied)
    << "a trusted certificate over a None channel must not grant an Application-criteria Role";

  // Conjunct 1 failing alone: a second client whose certificate carries the
  // same ApplicationUri - so the criteria string still matches - but which is
  // absent from the server's trust list, over a signed channel.
  auto untrustedCertResult = mCrypto->try_create_self_signed_application_instance_certificate_sync(
    Crypto::Name{.commonName = "Untrusted RBAC Client"},
    UtcTime{2050, 1, 1, 0, 0, 0},
    Crypto::SubjectAlternateName{.hostnames = {"localhost"}, .uris = {"urn:test:compliance:client"}},
    CertificateType::RsaSha256Application,
    2048);
  ASSERT_THAT(untrustedCertResult, ua::test_helpers::Good());
  auto [untrustedKeys, untrustedCert] = std::move(untrustedCertResult).value();

  auto untrustedStorePath = mTempDir / "rbac_untrusted_store";
  std::filesystem::create_directories(untrustedStorePath);
  TrustListValidationOptions validationOptions;
  auto untrustedCertStore = CertificateStoreFiles::create(mClientThreadPool.executor(),
    mCrypto,
    {.trustListPath = untrustedStorePath, .validationOptions = validationOptions});

  CertificateStore::ApplicationCertificate appCert;
  appCert.certificateType = CertificateType::RsaSha256Application;
  appCert.certificate = untrustedCert;
  appCert.keys = std::move(untrustedKeys);
  untrustedCertStore->add_to_application_certificates_sync(appCert);
  // Trust the server so only the server-side trust verdict is under test.
  untrustedCertStore->add_to_trusted_certificates_sync(mServerCert);

  auto untrustedAppCfg = ua::test_utils::create_test_config();
  untrustedAppCfg.application_description_part().applicationUri = "urn:test:compliance:client";
  client::CreateConfig untrustedClientCfg{
    .identity = ApplicationIdentity::load_default(), .application = std::move(untrustedAppCfg)};
  auto untrustedClient = Client::create(mClientThreadPool.executor(),
    std::move(untrustedClientCfg),
    ua::client::ClientComponents{.crypto = mCrypto,
      .applicationGroupCertificateStore = untrustedCertStore,
      .logSink = ua::test_helpers::test_log_sink(),
      .logLevel = LogLevel::Debug});

  CoreClient::OpenChannelConfig untrustedChannelCfg;
  untrustedChannelCfg.endpointUrl = mEndpointUrl;
  untrustedChannelCfg.securityMode = MessageSecurityMode::Sign;
  untrustedChannelCfg.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  untrustedChannelCfg.serverCertificate = mServerCert;

  auto channelResult = untrustedClient.core().try_open_channel_sync(std::move(untrustedChannelCfg));
  const bool channelRefused = channelResult.is_bad();
  bool roleGrantedToUntrustedCert{false};
  if (!channelRefused)
  {
    auto untrustedChannel = std::move(channelResult).value();
    auto sessionResult = untrustedChannel.try_create_session_sync({.sessionName = "AppCriteriaUntrusted"});
    if (sessionResult.is_good())
    {
      auto untrustedSession = std::move(sessionResult).value();
      if (untrustedSession.try_activate_sync().is_good())
      {
        auto resp = untrustedSession.attributes().read_sync(read_value(mTestVariable));
        roleGrantedToUntrustedCert = resp.response_header().service_result().is_good() &&
                                     !resp.results().empty() &&
                                     resp.results()[0].status().value_or(StatusCode{Status::Good}).is_good();
      }
      (void)untrustedSession.try_close_sync();
    }
    (void)untrustedChannel.try_close_sync();
  }

  EXPECT_FALSE(roleGrantedToUntrustedCert)
    << "an untrusted certificate over a signed channel must not grant an Application-criteria Role, even "
       "though the ApplicationUri matches the criteria entry; the SecureChannel was "
    << (channelRefused ? "refused at OPN" : "established");
}
