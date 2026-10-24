// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for `RoleConfiguration` - the identity-to-role mapping used to
/// construct each immutable `AccessIdentity`.
///
/// These tests pin:
///   * `add_role` / `remove_role` storage semantics + bit-collision rejection.
///   * `add_well_known_defaults` seeds Anonymous (bit 0) + AuthenticatedUser
///     (bit 1) with correct identity rules.
///   * `evaluate_roles` matches across every supported `IdentityCriteriaType`.
///   * Application include/exclude filter pre-scan (Q-RBAC-4 fail-fast).
///   * `epoch()` increments on every mutation; never decreases.
///   * Concurrent reads under shared_mutex contention.

#include <gtest/gtest.h>

#include "ua_claim_keys.h"
#include "ua_endpoint_type.h"
#include "ua_exceptions.h"
#include "ua_message_security_mode.h"
#include "ua_object_id.h"
#include "ua_role_configuration.h"
#include "ua_server_authentication.h"
#include "ua_utilities.h"
#include "ua_well_known_role_permissions.h"

#include <atomic>
#include <latch>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::server;

namespace
{

NodeId anonymous_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Anonymous)};
}

NodeId authenticated_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_AuthenticatedUser)};
}

NodeId observer_role_id()
{
  return NodeId{0, static_cast<uint32_t>(ObjectId::WellKnownRole_Observer)};
}

NodeId custom_role_id(uint32_t i)
{
  return NodeId{1, i};
}

IdentityMappingRuleType make_rule(IdentityCriteriaType type, std::string criteria = {})
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = type;
  rule.criteria() = String{criteria};
  return rule;
}

RoleConfiguration::RoleDefinition role(NodeId id, uint8_t bit, std::vector<IdentityMappingRuleType> rules)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = std::move(id);
  def.roleBit = bit;
  def.identities = std::move(rules);
  return def;
}

UserIdentity make_user(
  UserTokenKind kind, std::string name = {}, std::unordered_map<std::string, std::string> claims = {})
{
  UserIdentity user;
  user.userId = std::move(name);
  user.displayName = user.userId;
  user.kind = kind;
  user.claims = std::move(claims);
  return user;
}

EndpointSecurityContext make_security(
  MessageSecurityMode mode = MessageSecurityMode::None, std::string_view verifiedApplicationUri = {})
{
  EndpointSecurityContext sec;
  sec.messageSecurityMode = mode;
  sec.securityPolicyId = SecurityPolicyId::None;
  sec.endpointPolicyId = "L/None";
  sec.clientApplicationUri = String{verifiedApplicationUri};
  sec.endpointUrl = String{"opc.tcp://test/None"};
  sec.transportProfileUri = String{"http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"};
  return sec;
}

EndpointType make_endpoint_url_only(std::string_view url)
{
  EndpointType ep;
  ep.endpoint_url() = String{url};
  return ep;
}

// ============================================================================
// add_role / remove_role / epoch
// ============================================================================

// @relation(AC-SVR-AUTHZ-025-CLAIM-PATH-ADMINISTERS-NS0, scope=function)
TEST(ClaimKeysTest, PublishesEveryClaimKeyInterpretedByTheSdk)
{
  EXPECT_EQ(ClaimKeys::applicationUri, "app:uri");
  EXPECT_EQ(ClaimKeys::clientCertificateTrusted, "client_cert_trusted");
  EXPECT_EQ(ClaimKeys::diagnosticsFull, "diagnostics:full");
  EXPECT_EQ(ClaimKeys::diagnosticsSummary, "diagnostics:summary");
  EXPECT_EQ(ClaimKeys::group, "group");
  EXPECT_EQ(ClaimKeys::role, "role");
  EXPECT_EQ(ClaimKeys::thumbprint, "thumbprint");
  EXPECT_EQ(ClaimKeys::x509Subject, "x509:subject");
}

TEST(RoleConfigurationTest, EmptyByDefault)
{
  RoleConfiguration config;
  EXPECT_EQ(config.role_count(), 0u);
  EXPECT_EQ(config.epoch(), 1u);
}

// @relation(AC-SVR-AUTHZ-030-DECLARATIVE-WELL-KNOWN-GRANTS, scope=function)
TEST(RoleConfigurationTest, DeclarativeWellKnownGrantsDeriveAndMergeRoleDefinitions)
{
  auto config = RoleConfiguration::from_well_known_grants({
    {WellKnownRole::Observer, IdentityCriteriaType::Anonymous},
    {WellKnownRole::Observer, IdentityCriteriaType::AuthenticatedUser},
    {WellKnownRole::Engineer, IdentityCriteriaType::AuthenticatedUser},
  });

  ASSERT_NE(config, nullptr);
  EXPECT_EQ(config->role_count(), 2u);
  EXPECT_EQ(config->role_bit(observer_role_id()), 2);
  const NodeId engineerRoleId{ObjectId::WellKnownRole_Engineer};
  EXPECT_EQ(config->role_bit(engineerRoleId), 4);

  const auto observer = config->get_role(observer_role_id());
  ASSERT_TRUE(observer.has_value());
  ASSERT_EQ(observer->identities.size(), 2u);
  EXPECT_EQ(observer->identities[0].criteria_type(), IdentityCriteriaType::Anonymous);
  EXPECT_EQ(observer->identities[1].criteria_type(), IdentityCriteriaType::AuthenticatedUser);

  const auto anonymousRoles = config->evaluate_role_ids(make_user(UserTokenKind::Anonymous), make_security());
  EXPECT_EQ(anonymousRoles, std::vector<NodeId>{observer_role_id()});

  const auto authenticatedRoles =
    config->evaluate_role_ids(make_user(UserTokenKind::UserName, "alice"), make_security());
  EXPECT_EQ(authenticatedRoles, (std::vector<NodeId>{observer_role_id(), engineerRoleId}));
}

// @relation(AC-SVR-AUTHZ-030-ONE-ROLE-SET-AUTHORS-IDENTITY-AND-NAMESPACE, scope=function)
TEST(RoleConfigurationTest, OneRoleSpanAuthorsSharedIdentityRule)
{
  const auto roles = well_known_roles();
  auto config = RoleConfiguration::from_well_known_grants(roles, IdentityCriteriaType::Anonymous);

  ASSERT_NE(config, nullptr);
  ASSERT_EQ(config->role_count(), roles.size());

  std::vector<NodeId> expectedRoleIds;
  expectedRoleIds.reserve(roles.size());
  for (const auto roleValue : roles)
  {
    const auto expectedBit = well_known_role_bit(roleValue);
    ASSERT_TRUE(expectedBit.has_value());
    EXPECT_EQ(config->role_bit(well_known_role_node_id(roleValue)), expectedBit);
    expectedRoleIds.push_back(well_known_role_node_id(roleValue));
  }

  EXPECT_EQ(config->evaluate_role_ids(make_user(UserTokenKind::Anonymous), make_security()), expectedRoleIds);
}

// @relation(AC-SVR-AUTHZ-030-INVALID-GRANT-RETAINS-CAUSE, scope=function)
TEST(RoleConfigurationTest, DeclarativeWellKnownGrantRetainsMalformedCriteriaCause)
{
  try
  {
    (void)RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Observer, IdentityCriteriaType::Thumbprint, String{"GG"}}});
    FAIL() << "Malformed thumbprint grant was accepted";
  }
  catch (const UaException& exception)
  {
    EXPECT_EQ(exception.status(), Status::BadConfigurationError);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "WellKnownRoleGrantInvalidRule");
    EXPECT_EQ(exception.detail()->innerStatus, StatusCode{Status::BadInvalidArgument}.value());
    ASSERT_NE(exception.detail()->cause, nullptr);
    EXPECT_EQ(exception.detail()->cause->code, "IdentityRuleThumbprintMalformed");
  }
}

// @relation(AC-SVR-AUTHZ-030-INVALID-GRANT-RETAINS-CAUSE, scope=function)
TEST(RoleConfigurationTest, DeclarativeWellKnownGrantRetainsDuplicateCause)
{
  try
  {
    (void)RoleConfiguration::from_well_known_grants({
      {WellKnownRole::Observer, IdentityCriteriaType::Anonymous},
      {WellKnownRole::Observer, IdentityCriteriaType::Anonymous},
    });
    FAIL() << "Duplicate declarative grant was accepted";
  }
  catch (const UaException& exception)
  {
    EXPECT_EQ(exception.status(), Status::BadConfigurationError);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "WellKnownRoleGrantInvalidRule");
    EXPECT_EQ(exception.detail()->innerStatus, StatusCode{Status::BadEntryExists}.value());
    ASSERT_NE(exception.detail()->cause, nullptr);
    EXPECT_EQ(exception.detail()->cause->code, "IdentityRuleDuplicate");
  }
}

// @relation(AC-SVR-AUTHZ-030-INVALID-GRANT-RETAINS-CAUSE, scope=function)
TEST(RoleConfigurationTest, DeclarativeWellKnownGrantRejectsInvalidRoleValue)
{
  try
  {
    (void)RoleConfiguration::from_well_known_grants(
      {{static_cast<WellKnownRole>(255), IdentityCriteriaType::Anonymous}});
    FAIL() << "Invalid well-known Role value was accepted";
  }
  catch (const UaException& exception)
  {
    EXPECT_EQ(exception.status(), Status::BadConfigurationError);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "WellKnownRoleGrantInvalidRole");
    EXPECT_EQ(exception.detail()->innerStatus, StatusCode{Status::Good}.value());
    EXPECT_EQ(exception.detail()->cause, nullptr);
  }
}

TEST(RoleConfigurationTest, AddRoleStoresAndBumpsEpoch)
{
  RoleConfiguration config;
  const uint64_t before = config.epoch();
  EXPECT_TRUE(config.add_role(role(anonymous_role_id(), 0, {make_rule(IdentityCriteriaType::Anonymous)})));
  EXPECT_EQ(config.role_count(), 1u);
  EXPECT_GT(config.epoch(), before);
  EXPECT_EQ(config.role_bit(anonymous_role_id()).value_or(0xff), 0);
}

TEST(RoleConfigurationTest, AddRoleRejectsBitCollision)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(anonymous_role_id(), 0, {make_rule(IdentityCriteriaType::Anonymous)})));
  const uint64_t afterFirst = config.epoch();

  // Different role id, same bit -> reject, epoch must not move.
  EXPECT_FALSE(
    config.add_role(role(authenticated_role_id(), 0, {make_rule(IdentityCriteriaType::AuthenticatedUser)})));
  EXPECT_EQ(config.epoch(), afterFirst);
  EXPECT_EQ(config.role_count(), 1u);
}

TEST(RoleConfigurationTest, AddRoleRejectsBitOutOfRange)
{
  RoleConfiguration config;
  EXPECT_FALSE(config.add_role(role(custom_role_id(99), 64, {})));
  EXPECT_FALSE(config.add_role(role(custom_role_id(100), 255, {})));
  EXPECT_EQ(config.role_count(), 0u);
}

TEST(RoleConfigurationTest, AddRoleOverwritesSameRoleId)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(anonymous_role_id(), 0, {make_rule(IdentityCriteriaType::Anonymous)})));
  const uint64_t afterFirst = config.epoch();
  // Replace the role's mapping rules; bit unchanged.
  ASSERT_TRUE(
    config.add_role(role(anonymous_role_id(), 0, {make_rule(IdentityCriteriaType::UserName, "alice")})));
  EXPECT_EQ(config.role_count(), 1u);
  EXPECT_GT(config.epoch(), afterFirst);

  auto stored = config.get_role(anonymous_role_id());
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(stored->identities.size(), 1u);
  EXPECT_EQ(stored->identities[0].criteria_type(), IdentityCriteriaType::UserName);
}

TEST(RoleConfigurationTest, RemoveRolePresentBumpsEpoch)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(anonymous_role_id(), 0, {make_rule(IdentityCriteriaType::Anonymous)})));
  const uint64_t afterAdd = config.epoch();
  EXPECT_TRUE(config.remove_role(anonymous_role_id()));
  EXPECT_EQ(config.role_count(), 0u);
  EXPECT_GT(config.epoch(), afterAdd);
}

TEST(RoleConfigurationTest, RemoveRoleAbsentNoEpochBump)
{
  RoleConfiguration config;
  const uint64_t before = config.epoch();
  EXPECT_FALSE(config.remove_role(anonymous_role_id()));
  EXPECT_EQ(config.epoch(), before);
}

// @relation(SVR-SECADMIN-059, SVR-SECADMIN-060, scope=function)
TEST(RoleConfigurationTest, AddWellKnownDefaultsSeedsAnonymousAndAuthenticated)
{
  RoleConfiguration config;
  config.add_well_known_defaults();
  EXPECT_EQ(config.role_count(), 2u);
  EXPECT_EQ(config.role_bit(anonymous_role_id()).value_or(0xff), 0);
  EXPECT_EQ(config.role_bit(authenticated_role_id()).value_or(0xff), 1);

  // Part 18 section 4.3 L408-414: Anonymous Role ships with BOTH the Anonymous
  // and AuthenticatedUser default identity mapping rules. CTT v1.05.06
  // `Security Role Well Known Group 2/002.js` cert-enforces both.
  auto anon = config.get_role(anonymous_role_id());
  ASSERT_TRUE(anon.has_value());
  ASSERT_EQ(anon->identities.size(), 2u);
  EXPECT_EQ(anon->identities[0].criteria_type(), IdentityCriteriaType::Anonymous);
  EXPECT_EQ(anon->identities[1].criteria_type(), IdentityCriteriaType::AuthenticatedUser);

  auto authed = config.get_role(authenticated_role_id());
  ASSERT_TRUE(authed.has_value());
  ASSERT_EQ(authed->identities.size(), 1u);
  EXPECT_EQ(authed->identities[0].criteria_type(), IdentityCriteriaType::AuthenticatedUser);
}

// ============================================================================
// evaluate_roles - identity matching
// ============================================================================

// @relation(SVR-SECADMIN-059, scope=function)
TEST(RoleConfigurationTest, EvaluateMatchesAnonymousRule)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(anonymous_role_id(), 0, {make_rule(IdentityCriteriaType::Anonymous)})));

  const auto anon = make_user(UserTokenKind::Anonymous);
  const auto named = make_user(UserTokenKind::UserName, "alice");
  const auto sec = make_security();

  EXPECT_EQ(config.evaluate_roles(anon, sec), uint64_t{1} << 0);
  EXPECT_EQ(config.evaluate_roles(named, sec), 0u) << "AuthenticatedUser must not match Anonymous rule";
}

// @relation(SVR-SECADMIN-060, scope=function)
TEST(RoleConfigurationTest, EvaluateMatchesAuthenticatedUserRule)
{
  RoleConfiguration config;
  ASSERT_TRUE(
    config.add_role(role(authenticated_role_id(), 1, {make_rule(IdentityCriteriaType::AuthenticatedUser)})));

  const auto anon = make_user(UserTokenKind::Anonymous);
  const auto named = make_user(UserTokenKind::UserName, "alice");

  EXPECT_EQ(config.evaluate_roles(anon, make_security()), 0u);
  EXPECT_EQ(config.evaluate_roles(named, make_security()), uint64_t{1} << 1);
}

// @relation(SVR-SECADMIN-029, scope=function)
TEST(RoleConfigurationTest, EvaluateMatchesUserNameRule)
{
  RoleConfiguration config;
  ASSERT_TRUE(
    config.add_role(role(custom_role_id(10), 2, {make_rule(IdentityCriteriaType::UserName, "alice")})));

  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), make_security()), uint64_t{1} << 2);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "bob"), make_security()), 0u);
}

TEST(RoleConfigurationTest, EvaluateMatchesGroupIdRule)
{
  RoleConfiguration config;
  ASSERT_TRUE(
    config.add_role(role(custom_role_id(11), 3, {make_rule(IdentityCriteriaType::GroupId, "engineering")})));

  EXPECT_EQ(config.evaluate_roles(
              make_user(UserTokenKind::UserName, "alice", {{"group", "engineering"}}), make_security()),
    uint64_t{1} << 3);
  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice", {{"group", "ops"}}), make_security()),
    0u);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), make_security()), 0u);
}

// @relation(SVR-SECADMIN-031, scope=function)
TEST(RoleConfigurationTest, EvaluateMatchesThumbprintRule)
{
  RoleConfiguration config;
  ASSERT_TRUE(
    config.add_role(role(custom_role_id(12), 4, {make_rule(IdentityCriteriaType::Thumbprint, "ABCD")})));

  EXPECT_EQ(config.evaluate_roles(
              make_user(UserTokenKind::X509, "device", {{"thumbprint", "ABCD"}}), make_security()),
    uint64_t{1} << 4);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::X509, "device"), make_security()), 0u);
}

TEST(RoleConfigurationTest, EvaluateMatchesRoleClaimRule)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(custom_role_id(13), 5, {make_rule(IdentityCriteriaType::Role, "admin")})));

  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice", {{"role", "admin"}}), make_security()),
    uint64_t{1} << 5);
  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice", {{"role", "viewer"}}), make_security()),
    0u);
}

// @relation(SVR-SECADMIN-033, scope=function)
TEST(RoleConfigurationTest, EvaluateMatchesX509SubjectRule)
{
  // X509Subject criteria are stored in the Table-8-ordered, double-quoted
  // canonical form per Part 18 section 4.4.3 L793-808. Both the configured rule
  // and the user-side `x509:subject` claim go through the canonicaliser
  // before comparison.
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(
    role(custom_role_id(14), 6, {make_rule(IdentityCriteriaType::X509Subject, R"(CN="alice")")})));

  EXPECT_EQ(config.evaluate_roles(
              make_user(UserTokenKind::X509, "alice", {{"x509:subject", R"(CN="alice")"}}), make_security()),
    uint64_t{1} << 6);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::X509, "alice"), make_security()), 0u);
}

TEST(RoleConfigurationTest, EvaluateMatchesApplicationRule)
{
  // Application criteria match per Part 18 section 4.4.3 L785-788 require BOTH a
  // trusted client certificate AND a signed-or-better channel. Tests stand
  // in for the trust-list integration via the `client_cert_trusted=true`
  // claim populated by the authentication layer.
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(
    role(custom_role_id(15), 7, {make_rule(IdentityCriteriaType::Application, "urn:client:app:1")})));

  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice", {{"client_cert_trusted", "true"}}),
      make_security(MessageSecurityMode::SignAndEncrypt, "urn:client:app:1")),
    uint64_t{1} << 7);
  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice", {{"client_cert_trusted", "true"}}),
      make_security(MessageSecurityMode::SignAndEncrypt, "urn:client:other")),
    0u);
}

TEST(RoleConfigurationTest, EvaluateOrAcrossMultipleRulesWithinRole)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(custom_role_id(20),
    8,
    {make_rule(IdentityCriteriaType::UserName, "alice"), make_rule(IdentityCriteriaType::UserName, "bob")})));

  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), make_security()), uint64_t{1} << 8);
  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "bob"), make_security()), uint64_t{1} << 8);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "carol"), make_security()), 0u);
}

TEST(RoleConfigurationTest, EvaluateUnionsAcrossRoles)
{
  RoleConfiguration config;
  config.add_well_known_defaults();
  ASSERT_TRUE(
    config.add_role(role(observer_role_id(), 2, {make_rule(IdentityCriteriaType::UserName, "alice")})));

  const auto alice = make_user(UserTokenKind::UserName, "alice");
  const uint64_t got = config.evaluate_roles(alice, make_security());
  EXPECT_NE(got & (uint64_t{1} << 1), 0u) << "AuthenticatedUser bit must be set";
  EXPECT_NE(got & (uint64_t{1} << 2), 0u) << "Observer bit must be set";
  // Part 18 section 4.3 L408-414: Anonymous Role's default Identities now contains
  // both Anonymous AND AuthenticatedUser criteria, so any authenticated user
  // inherits the Anonymous role too. Anything granted only to Anonymous
  // remains reachable after authentication.
  EXPECT_NE(got & (uint64_t{1} << 0), 0u)
    << "Anonymous bit must also be set for authenticated users (dual-rule semantics)";
}

// @relation(AC-SVR-AUTHZ-025-UNREGISTERED-ROLE-IS-A-DISTINCT-CAUSE, scope=function)
TEST(RoleConfigurationTest, EvaluateRoleIdsUsesTheSameRulesAndPreservesConfigurationOrder)
{
  RoleConfiguration config;
  const NodeId first = custom_role_id(21);
  const NodeId filtered = custom_role_id(22);
  const NodeId second = custom_role_id(23);
  ASSERT_TRUE(config.add_role(role(first, 3, {make_rule(IdentityCriteriaType::UserName, "alice")})));

  auto filteredRole = role(filtered, 4, {make_rule(IdentityCriteriaType::UserName, "alice")});
  filteredRole.endpoints = {make_endpoint_url_only("opc.tcp://other/None")};
  ASSERT_TRUE(config.add_role(std::move(filteredRole)));
  ASSERT_TRUE(config.add_role(role(second, 5, {make_rule(IdentityCriteriaType::AuthenticatedUser)})));

  EXPECT_EQ(config.evaluate_role_ids(make_user(UserTokenKind::UserName, "alice"), make_security()),
    (std::vector<NodeId>{first, second}));

  const auto evaluation =
    config.evaluate_access_identity(make_user(UserTokenKind::UserName, "alice"), make_security());
  EXPECT_EQ(evaluation.grantedRoles, (std::vector<NodeId>{first, second}));
  EXPECT_EQ(evaluation.registeredRoles, (std::vector<NodeId>{first, filtered, second}));
  EXPECT_EQ(evaluation.configurationEpoch, config.epoch());
}

// ============================================================================
// Application filter pre-scan (Q-RBAC-4 fail-fast)
// ============================================================================

TEST(RoleConfigurationTest, ApplicationIncludeFilterAllowsListedApp)
{
  // Applications-filtered Role requires at least a signed channel per
  // Part 18 section 4.4.1 L665-671 (SECADMIN-029) - use SignAndEncrypt.
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(30), 9, {make_rule(IdentityCriteriaType::UserName, "alice")});
  def.applications = {String{"urn:trusted:client"}};
  def.applicationsExclude = false;
  ASSERT_TRUE(config.add_role(std::move(def)));

  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"),
              make_security(MessageSecurityMode::SignAndEncrypt, "urn:trusted:client")),
    uint64_t{1} << 9);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"),
              make_security(MessageSecurityMode::SignAndEncrypt, "urn:other")),
    0u)
    << "App URI not in include list -> role skipped before rule evaluation";
}

TEST(RoleConfigurationTest, ApplicationExcludeFilterRejectsListedApp)
{
  // Applications-filtered Role requires at least a signed channel per
  // Part 18 section 4.4.1 L665-671 (SECADMIN-029) - use SignAndEncrypt.
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(31), 10, {make_rule(IdentityCriteriaType::UserName, "alice")});
  def.applications = {String{"urn:blocked:client"}};
  def.applicationsExclude = true;
  ASSERT_TRUE(config.add_role(std::move(def)));

  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"),
              make_security(MessageSecurityMode::SignAndEncrypt, "urn:blocked:client")),
    0u);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"),
              make_security(MessageSecurityMode::SignAndEncrypt, "urn:other")),
    uint64_t{1} << 10);
}

TEST(RoleConfigurationTest, ApplicationIncludeRejectsMissingClaim)
{
  // Applications-filtered Role requires at least a signed channel per
  // Part 18 section 4.4.1 L665-671 (SECADMIN-029) - use SignAndEncrypt.
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(32), 11, {make_rule(IdentityCriteriaType::UserName, "alice")});
  def.applications = {String{"urn:trusted"}};
  def.applicationsExclude = false;
  ASSERT_TRUE(config.add_role(std::move(def)));

  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"),
              make_security(MessageSecurityMode::SignAndEncrypt)),
    0u);
}

// @relation(AC-SVR-SECADMIN-008-CREATESESSION-URI-BINDING, scope=function)
TEST(RoleConfigurationTest, ApplicationFiltersIgnoreUnverifiedAuthenticatorApplicationClaim)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition definition =
    role(custom_role_id(33), 12, {make_rule(IdentityCriteriaType::UserName, "alice")});
  definition.applications = {String{"urn:trusted"}};
  ASSERT_TRUE(config.add_role(std::move(definition)));

  const auto forgedClaim = make_user(UserTokenKind::UserName, "alice", {{"app:uri", "urn:trusted"}});
  EXPECT_EQ(config.evaluate_roles(forgedClaim, make_security(MessageSecurityMode::SignAndEncrypt)), 0u);
  EXPECT_EQ(
    config.evaluate_roles(forgedClaim, make_security(MessageSecurityMode::SignAndEncrypt, "urn:trusted")),
    uint64_t{1} << 12);
}

// ============================================================================
// Concurrency
// ============================================================================

TEST(RoleConfigurationTest, ConcurrentEvaluatesAndMutationsStaySane)
{
  RoleConfiguration config;
  config.add_well_known_defaults();

  std::atomic<bool> stop{false};
  std::atomic<size_t> reads{0};
  std::atomic<size_t> mutations{0};
  std::latch readersStarted{4};

  std::vector<std::thread> readers;
  for (int i = 0; i < 4; ++i)
  {
    readers.emplace_back(
      [&]
      {
        const auto user = make_user(UserTokenKind::UserName, "alice");
        const auto sec = make_security();
        (void)config.evaluate_roles(user, sec);
        (void)config.epoch();
        reads.fetch_add(1, std::memory_order_relaxed);
        readersStarted.count_down();
        while (!stop.load(std::memory_order_relaxed))
        {
          (void)config.evaluate_roles(user, sec);
          (void)config.epoch();
          reads.fetch_add(1, std::memory_order_relaxed);
        }
      });
  }

  // Do not let the fast writer finish and set stop before a reader is ever scheduled. This barrier makes
  // the concurrency stimulus deterministic while leaving the read/mutation overlap and assertions intact.
  readersStarted.wait();
  std::thread writer(
    [&]
    {
      for (int i = 0; i < 200; ++i)
      {
        RoleConfiguration::RoleDefinition def;
        def.roleId = custom_role_id(static_cast<uint32_t>(100 + i));
        def.roleBit = static_cast<uint8_t>(2 + (i % 30));
        def.identities = {make_rule(IdentityCriteriaType::UserName, "alice")};
        if (config.add_role(std::move(def)))
        {
          config.remove_role(custom_role_id(static_cast<uint32_t>(100 + i)));
          mutations.fetch_add(2, std::memory_order_relaxed);
        }
      }
    });

  writer.join();
  stop.store(true, std::memory_order_relaxed);
  for (auto& t : readers)
  {
    t.join();
  }

  EXPECT_GT(reads.load(), 0u);
  EXPECT_GT(mutations.load(), 0u);
  // Final state: well-known defaults must still be present and unchanged.
  EXPECT_EQ(config.role_count(), 2u);
  EXPECT_EQ(config.role_bit(anonymous_role_id()).value_or(0xff), 0);
  EXPECT_EQ(config.role_bit(authenticated_role_id()).value_or(0xff), 1);
}

// ============================================================================
// add_custom_role - bit slot allocator
// ============================================================================

TEST(RoleConfigurationTest, AddCustomRoleAllocatesFreeBitSlot)
{
  RoleConfiguration config;
  config.add_well_known_defaults();  // bits 0, 1
  const uint64_t before = config.epoch();

  RoleConfiguration::RoleDefinition def;
  def.roleId = custom_role_id(40);
  // roleBit input is ignored - allocator picks a free slot.
  def.roleBit = 0xff;
  def.identities = {make_rule(IdentityCriteriaType::UserName, "alice")};

  auto allocated = config.add_custom_role(std::move(def));
  ASSERT_TRUE(allocated.has_value());
  EXPECT_GE(*allocated, 2u) << "Allocator must skip bits 0 and 1 already used by well-known defaults";
  EXPECT_LT(*allocated, 64u);
  EXPECT_EQ(config.role_bit(custom_role_id(40)).value_or(0xff), *allocated);
  EXPECT_GT(config.epoch(), before);
}

TEST(RoleConfigurationTest, AddCustomRoleReusesFreedSlot)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def;
  def.roleId = custom_role_id(41);
  def.identities = {make_rule(IdentityCriteriaType::UserName, "alice")};
  auto firstSlot = config.add_custom_role(def);
  ASSERT_TRUE(firstSlot.has_value());

  ASSERT_TRUE(config.remove_role(custom_role_id(41)));

  RoleConfiguration::RoleDefinition replacement;
  replacement.roleId = custom_role_id(42);
  replacement.identities = {make_rule(IdentityCriteriaType::UserName, "bob")};
  auto secondSlot = config.add_custom_role(std::move(replacement));
  ASSERT_TRUE(secondSlot.has_value());
  EXPECT_EQ(*secondSlot, *firstSlot) << "Freed slot must be reused";
}

TEST(RoleConfigurationTest, AddCustomRoleRejectsDuplicateRoleId)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def;
  def.roleId = custom_role_id(43);
  def.identities = {make_rule(IdentityCriteriaType::UserName, "alice")};
  ASSERT_TRUE(config.add_custom_role(def).has_value());
  EXPECT_FALSE(config.add_custom_role(def).has_value());
}

TEST(RoleConfigurationTest, AddCustomRoleFailsWhenAllSlotsExhausted)
{
  RoleConfiguration config;
  for (uint32_t i = 0; i < 64; ++i)
  {
    RoleConfiguration::RoleDefinition def;
    def.roleId = custom_role_id(200 + i);
    auto slot = config.add_custom_role(std::move(def));
    ASSERT_TRUE(slot.has_value()) << "slot " << i;
  }
  RoleConfiguration::RoleDefinition overflow;
  overflow.roleId = custom_role_id(300);
  EXPECT_FALSE(config.add_custom_role(std::move(overflow)).has_value());
}

// ============================================================================
// Per-rule mutators
// ============================================================================

TEST(RoleConfigurationTest, AddIdentityRuleAppendsAndBumpsEpoch)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(observer_role_id(), 2, {})));
  const auto before = config.epoch();

  auto result =
    config.add_identity_rule(observer_role_id(), make_rule(IdentityCriteriaType::UserName, "alice"));
  EXPECT_TRUE(result.is_good());
  EXPECT_GT(config.epoch(), before);

  auto stored = config.get_role(observer_role_id());
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(stored->identities.size(), 1u);
  EXPECT_EQ(stored->identities[0].criteria_type(), IdentityCriteriaType::UserName);
}

TEST(RoleConfigurationTest, AddIdentityRuleRejectsDuplicates)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(observer_role_id(), 2, {})));
  auto rule = make_rule(IdentityCriteriaType::UserName, "alice");
  ASSERT_TRUE(config.add_identity_rule(observer_role_id(), rule).is_good());
  const auto after = config.epoch();
  auto dupe = config.add_identity_rule(observer_role_id(), rule);
  EXPECT_TRUE(dupe.is_bad());
  EXPECT_EQ(dupe.status_code(), Status::BadEntryExists);
  EXPECT_EQ(config.epoch(), after) << "Rejected duplicate must not bump epoch";
}

TEST(RoleConfigurationTest, AddIdentityRuleRejectsUnknownRole)
{
  RoleConfiguration config;
  auto result =
    config.add_identity_rule(custom_role_id(999), make_rule(IdentityCriteriaType::UserName, "alice"));
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadNotFound);
}

// @relation(AC-SVR-AUTHZ-025-EMPTY-CRITERIA-REFUSED, scope=function)
TEST(RoleConfigurationTest, EmptyCriteriaRuleIsRefused)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(observer_role_id(), 2, {})));

  for (const auto type : {IdentityCriteriaType::UserName,
         IdentityCriteriaType::Thumbprint,
         IdentityCriteriaType::Role,
         IdentityCriteriaType::GroupId,
         IdentityCriteriaType::Application,
         IdentityCriteriaType::X509Subject})
  {
    auto result = config.add_identity_rule(observer_role_id(), make_rule(type, ""));
    ASSERT_TRUE(result.is_bad()) << utils::to_underlying(type);
    EXPECT_EQ(result.status_code(), Status::BadInvalidArgument);
  }
  EXPECT_TRUE(config.get_role(observer_role_id())->identities.empty());
}

TEST(RoleConfigurationTest, RemoveIdentityRuleErasesAndBumpsEpoch)
{
  RoleConfiguration config;
  auto rule = make_rule(IdentityCriteriaType::UserName, "alice");
  ASSERT_TRUE(config.add_role(role(observer_role_id(), 2, {rule})));
  const auto before = config.epoch();
  EXPECT_TRUE(config.remove_identity_rule(observer_role_id(), rule));
  EXPECT_GT(config.epoch(), before);
  EXPECT_EQ(config.get_role(observer_role_id())->identities.size(), 0u);
}

TEST(RoleConfigurationTest, AddRemoveApplicationRoundTrips)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(observer_role_id(), 2, {})));
  EXPECT_TRUE(config.add_application(observer_role_id(), String{"urn:client:a"}));
  EXPECT_TRUE(config.add_application(observer_role_id(), String{"urn:client:b"}));
  EXPECT_FALSE(config.add_application(observer_role_id(), String{"urn:client:a"})) << "Duplicate rejected";
  ASSERT_EQ(config.get_role(observer_role_id())->applications.size(), 2u);
  EXPECT_TRUE(config.remove_application(observer_role_id(), String{"urn:client:a"}));
  EXPECT_FALSE(config.remove_application(observer_role_id(), String{"urn:client:a"}));
  EXPECT_EQ(config.get_role(observer_role_id())->applications.size(), 1u);
}

TEST(RoleConfigurationTest, AddRemoveEndpointRoundTrips)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(observer_role_id(), 2, {})));
  EXPECT_TRUE(config.add_endpoint(observer_role_id(), make_endpoint_url_only("opc.tcp://a/None")));
  EXPECT_TRUE(config.add_endpoint(observer_role_id(), make_endpoint_url_only("opc.tcp://a/SignAndEncrypt")));
  EXPECT_FALSE(config.add_endpoint(observer_role_id(), make_endpoint_url_only("opc.tcp://a/None")));
  ASSERT_EQ(config.get_role(observer_role_id())->endpoints.size(), 2u);
  EXPECT_TRUE(config.remove_endpoint(observer_role_id(), make_endpoint_url_only("opc.tcp://a/None")));
  EXPECT_EQ(config.get_role(observer_role_id())->endpoints.size(), 1u);
}

TEST(RoleConfigurationTest, SetExcludeFlagsBumpEpoch)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(observer_role_id(), 2, {})));
  const auto before = config.epoch();
  EXPECT_TRUE(config.set_applications_exclude(observer_role_id(), true));
  EXPECT_TRUE(config.set_endpoints_exclude(observer_role_id(), true));
  EXPECT_GT(config.epoch(), before);
  auto stored = config.get_role(observer_role_id());
  EXPECT_TRUE(stored->applicationsExclude);
  EXPECT_TRUE(stored->endpointsExclude);
}

TEST(RoleConfigurationTest, SetExcludeFlagNoOpDoesNotBumpEpoch)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role(observer_role_id(), 2, {})));
  ASSERT_TRUE(config.set_applications_exclude(observer_role_id(), true));
  const auto after = config.epoch();
  EXPECT_TRUE(config.set_applications_exclude(observer_role_id(), true));
  EXPECT_EQ(config.epoch(), after) << "No-op write must not bump epoch";
}

// ============================================================================
// Endpoint filter
// ============================================================================

// @relation(SVR-SECADMIN-034, scope=function)
TEST(RoleConfigurationTest, EndpointIncludeFilterAllowsListedEndpoint)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(50), 5, {make_rule(IdentityCriteriaType::UserName, "alice")});
  def.endpoints = {make_endpoint_url_only("opc.tcp://test/SignAndEncrypt")};
  def.endpointsExclude = false;
  ASSERT_TRUE(config.add_role(std::move(def)));

  EndpointSecurityContext secMatching = make_security();
  secMatching.endpointUrl = String{"opc.tcp://test/SignAndEncrypt"};
  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), secMatching), uint64_t{1} << 5);

  EndpointSecurityContext secOther = make_security();
  secOther.endpointUrl = String{"opc.tcp://test/None"};
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), secOther), 0u)
    << "Endpoint URL not in include list -> role skipped";
}

// @relation(SVR-SECADMIN-034, scope=function)
TEST(RoleConfigurationTest, EndpointExcludeFilterRejectsListedEndpoint)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(51), 6, {make_rule(IdentityCriteriaType::UserName, "alice")});
  def.endpoints = {make_endpoint_url_only("opc.tcp://test/None")};
  def.endpointsExclude = true;
  ASSERT_TRUE(config.add_role(std::move(def)));

  EndpointSecurityContext secBlocked = make_security();
  secBlocked.endpointUrl = String{"opc.tcp://test/None"};
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), secBlocked), 0u);

  EndpointSecurityContext secAllowed = make_security();
  secAllowed.endpointUrl = String{"opc.tcp://test/SignAndEncrypt"};
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), secAllowed), uint64_t{1} << 6);
}

// ============================================================================
// Endpoint filter - per-field narrowing per Part 18 section 4.4.2
// ============================================================================

// @relation(SVR-SECADMIN-034, scope=function)
TEST(RoleConfigurationTest, EndpointFilterNarrowsBySecurityMode)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(52), 7, {make_rule(IdentityCriteriaType::UserName, "alice")});
  EndpointType narrow;
  narrow.security_mode() = MessageSecurityMode::SignAndEncrypt;
  // URL/policyUri/TransportProfileUri default -> match anything.
  def.endpoints = {narrow};
  ASSERT_TRUE(config.add_role(std::move(def)));

  EndpointSecurityContext signEnc = make_security(MessageSecurityMode::SignAndEncrypt);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), signEnc), uint64_t{1} << 7);

  EndpointSecurityContext none = make_security(MessageSecurityMode::None);
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), none), 0u)
    << "Mode narrows: None must not match a SignAndEncrypt-pinned role";
}

// @relation(SVR-SECADMIN-034, scope=function)
TEST(RoleConfigurationTest, EndpointFilterNarrowsBySecurityPolicyUri)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(53), 8, {make_rule(IdentityCriteriaType::UserName, "alice")});
  EndpointType narrow;
  narrow.security_policy_uri() = utils::get_security_policy_uri(SecurityPolicyId::Basic256Sha256);
  def.endpoints = {narrow};
  ASSERT_TRUE(config.add_role(std::move(def)));

  EndpointSecurityContext basicSha = make_security();
  basicSha.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), basicSha), uint64_t{1} << 8);

  EndpointSecurityContext noneSec = make_security();
  noneSec.securityPolicyId = SecurityPolicyId::None;
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), noneSec), 0u);
}

// @relation(SVR-SECADMIN-034, scope=function)
TEST(RoleConfigurationTest, EndpointFilterNarrowsByTransportProfileUri)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(54), 9, {make_rule(IdentityCriteriaType::UserName, "alice")});
  EndpointType narrow;
  narrow.transport_profile_uri() = String{"http://opcfoundation.org/UA-Profile/Transport/https-uabinary"};
  def.endpoints = {narrow};
  ASSERT_TRUE(config.add_role(std::move(def)));

  EndpointSecurityContext https = make_security();
  https.transportProfileUri = String{"http://opcfoundation.org/UA-Profile/Transport/https-uabinary"};
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), https), uint64_t{1} << 9);

  EndpointSecurityContext opctcp = make_security();
  opctcp.transportProfileUri = String{"http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"};
  EXPECT_EQ(config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), opctcp), 0u);
}

// @relation(SVR-SECADMIN-034, scope=function)
TEST(RoleConfigurationTest, EndpointFilterAllDefaultEntryMatchesAny)
{
  // A stored EndpointType with all four fields at default values must match
  // any session - per section 4.4.2 default fields are "ignored for comparison",
  // so an all-default entry effectively matches everything.
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(55), 10, {make_rule(IdentityCriteriaType::UserName, "alice")});
  def.endpoints = {EndpointType{}};
  ASSERT_TRUE(config.add_role(std::move(def)));

  EXPECT_EQ(
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), make_security()), uint64_t{1} << 10);
}

// Part 18 section 4.4.2: an `EndpointType` field left at its default value is
// "ignored for comparison", so a rule entry carrying only an `EndpointUrl`
// covers that URL on every security mode, policy and transport. The natural
// implementation compares all four fields and inverts the filter: a default
// `securityMode` (Invalid) treated as a value to match would restrict the Role
// to endpoints whose mode is Invalid - i.e. to none of them - while the
// administrator sees a rule that reads correctly.
// @verifies AC-SVR-SECADMIN-034-ENDPOINT-NARROWING
TEST(RoleConfigurationTest, EndpointUrlOnlyEntryCoversThatUrlAtEverySecuritySetting)
{
  RoleConfiguration config;
  RoleConfiguration::RoleDefinition def =
    role(custom_role_id(56), 11, {make_rule(IdentityCriteriaType::UserName, "alice")});
  // Only EndpointUrl is set; security mode, policy URI and transport profile
  // URI stay at their defaults and must therefore narrow nothing.
  def.endpoints = {make_endpoint_url_only("opc.tcp://test/Shared")};
  def.endpointsExclude = false;
  ASSERT_TRUE(config.add_role(std::move(def)));

  const auto alice = make_user(UserTokenKind::UserName, "alice");
  const uint64_t expected = uint64_t{1} << 11;

  EndpointSecurityContext none = make_security(MessageSecurityMode::None);
  none.endpointUrl = String{"opc.tcp://test/Shared"};
  none.securityPolicyId = SecurityPolicyId::None;
  EXPECT_EQ(config.evaluate_roles(alice, none), expected)
    << "URL-only entry must match a None-mode endpoint at that URL";

  EndpointSecurityContext sign = make_security(MessageSecurityMode::Sign);
  sign.endpointUrl = String{"opc.tcp://test/Shared"};
  sign.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  EXPECT_EQ(config.evaluate_roles(alice, sign), expected)
    << "URL-only entry must match a Sign endpoint at that URL";

  EndpointSecurityContext signEncrypt = make_security(MessageSecurityMode::SignAndEncrypt);
  signEncrypt.endpointUrl = String{"opc.tcp://test/Shared"};
  signEncrypt.securityPolicyId = SecurityPolicyId::Aes256Sha256RsaPss;
  signEncrypt.transportProfileUri = String{"http://opcfoundation.org/UA-Profile/Transport/https-uabinary"};
  EXPECT_EQ(config.evaluate_roles(alice, signEncrypt), expected)
    << "URL-only entry must match a SignAndEncrypt endpoint at that URL, on any policy and transport";

  // The filter is still live: a different URL is excluded even though every
  // other field of the session matches an entry field that was left default.
  EndpointSecurityContext otherUrl = make_security(MessageSecurityMode::SignAndEncrypt);
  otherUrl.endpointUrl = String{"opc.tcp://test/Other"};
  EXPECT_EQ(config.evaluate_roles(alice, otherUrl), 0u)
    << "The one field that IS set must still narrow: a different URL is not covered";
}

// ============================================================================
// Well-known Role default Identities
// ============================================================================

// Part 18 section 4.3 / section 4.4: the AuthenticatedUser Role ships with a
// single AuthenticatedUser identity mapping rule and no Anonymous rule. The
// containment between the two well-known Roles runs one way only - Anonymous
// carries both rules, AuthenticatedUser carries one - so an implementation that
// seeds the pair symmetrically would hand every anonymous session the
// AuthenticatedUser Role and erase the distinction the two Roles exist to draw.
// @verifies AC-SVR-SECADMIN-060-AUTHENTICATEDUSER-IDENTITIES
TEST(RoleConfigurationTest, AuthenticatedUserRoleDefaultIdentitiesCarryNoAnonymousCriteria)
{
  RoleConfiguration config;
  config.add_well_known_defaults();

  auto authed = config.get_role(authenticated_role_id());
  ASSERT_TRUE(authed.has_value());
  ASSERT_EQ(authed->identities.size(), 1u) << "Exactly one default rule on the AuthenticatedUser Role";
  EXPECT_EQ(authed->identities[0].criteria_type(), IdentityCriteriaType::AuthenticatedUser);
  EXPECT_TRUE(authed->identities[0].criteria().empty())
    << "The AuthenticatedUser criteria entry carries an empty criteria string";
  for (const auto& rule : authed->identities)
  {
    EXPECT_NE(rule.criteria_type(), IdentityCriteriaType::Anonymous)
      << "No Anonymous criteria may appear on the AuthenticatedUser Role";
  }

  // The absence is the substance, so assert it through the evaluator on the
  // seeded defaults rather than on the stored array alone: an anonymous session
  // must not acquire the AuthenticatedUser Role, while an authenticated one must.
  const uint64_t authenticatedBit = uint64_t{1} << 1;
  ASSERT_EQ(config.role_bit(authenticated_role_id()).value_or(0xff), 1);

  const uint64_t anonymousSessionRoles =
    config.evaluate_roles(make_user(UserTokenKind::Anonymous), make_security());
  EXPECT_EQ(anonymousSessionRoles & authenticatedBit, 0u)
    << "An anonymous session must not be granted the AuthenticatedUser Role";

  const uint64_t namedSessionRoles =
    config.evaluate_roles(make_user(UserTokenKind::UserName, "alice"), make_security());
  EXPECT_EQ(namedSessionRoles & authenticatedBit, authenticatedBit)
    << "A non-anonymous session must be granted the AuthenticatedUser Role";
}

}  // namespace

// Part 18 section 4.4.4 Table 10: the UserName criterion names a UserName from a UserNameIdentityToken.
// An X.509 or issued identity whose user id equals that name is a different principal.
// @relation(AC-SVR-AUTHZ-018-USERNAME-CRITERION-BINDS-THE-TOKEN-KIND, scope=function)
TEST(RoleConfigurationTest, UserNameCriterionDoesNotMatchAnotherTokenKindWithTheSameUserId)
{
  RoleConfiguration config;
  ASSERT_TRUE(
    config.add_role(role(observer_role_id(), 2, {make_rule(IdentityCriteriaType::UserName, "operator")})));

  EXPECT_EQ(config.evaluate_role_ids(make_user(UserTokenKind::UserName, "operator"), make_security()),
    std::vector<NodeId>{observer_role_id()})
    << "control: the UserName user named by the rule holds the Role";
  EXPECT_TRUE(config.evaluate_role_ids(make_user(UserTokenKind::X509, "operator"), make_security()).empty())
    << "an X.509 identity whose user id is the same name must not match a UserName rule";
  EXPECT_TRUE(
    config.evaluate_role_ids(make_user(UserTokenKind::IssuedToken, "operator"), make_security()).empty())
    << "an issued-token identity whose user id is the same name must not match a UserName rule";
}
