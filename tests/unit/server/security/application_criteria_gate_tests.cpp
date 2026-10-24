// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for Part 18 section 4.4.3 L785-788 - the `Application` IdentityCriteria
/// gate.
///
/// Pins (SECADMIN-032): a Role whose `IdentityMappingRule` is of type
/// `Application` is granted only when BOTH gates clear:
///   1. The Session's channel is at least signed (`Sign` or `SignAndEncrypt`).
///   2. The Client's `ApplicationInstanceCertificate` is trusted by the
///      Server - surfaced to `RoleConfiguration` via the
///      `mClaims["client_cert_trusted"] = "true"` claim populated by the
///      authentication layer when the cert validates against the trust list.
///
/// Failure of either gate causes the rule to not-match (the Role is skipped,
/// not the request denied) so an unrelated identity rule on the same Role
/// can still grant it via a different path.

#include <gtest/gtest.h>

#include "ua_role_configuration.h"
#include "ua_server_authentication.h"

using namespace ua;
using namespace ua::server;

namespace
{

NodeId custom_role(uint32_t id)
{
  return NodeId{1, id};
}

IdentityMappingRuleType app_rule(std::string_view appUri)
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::Application;
  rule.criteria() = String{appUri};
  return rule;
}

RoleConfiguration::RoleDefinition role_with_app_criterion(uint8_t bit, std::string_view appUri)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = custom_role(70 + bit);
  def.roleBit = bit;
  def.identities = {app_rule(appUri)};
  return def;
}

// Per Part 18 section 4.4.3 L788-789: "[Application criteria] is used if a Role
// should be granted to a Session for Application Authentication with
// Anonymous UserIdentityToken." The canonical shape: Anonymous user-token
// kind (empty userId) on a signed channel whose client cert validates
// against the trust list (surfaced as `client_cert_trusted=true` by the
// session-side producer in `ua_server_session.cpp:commit_activate_identity`).
UserIdentity make_user(std::string appUri, bool trusted)
{
  UserIdentity user;
  user.userId = "";  // Anonymous user identity carries no user-name.
  user.kind = UserTokenKind::Anonymous;
  user.claims["app:uri"] = std::move(appUri);
  if (trusted)
  {
    user.claims["client_cert_trusted"] = "true";
  }
  return user;
}

EndpointSecurityContext make_security(MessageSecurityMode mode)
{
  EndpointSecurityContext sec;
  sec.messageSecurityMode = mode;
  sec.securityPolicyId =
    mode == MessageSecurityMode::None ? SecurityPolicyId::None : SecurityPolicyId::Basic256Sha256;
  sec.endpointPolicyId = "L/Test";
  sec.clientApplicationUri = String{"urn:trusted:client"};
  return sec;
}

}  // namespace

// Gate 2 (trusted cert) fails -> rule must not match even on an encrypted
// channel.
TEST(ApplicationCriteriaGate, UntrustedClientCertSuppressesArm)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role_with_app_criterion(0, "urn:trusted:client")));

  const auto user = make_user("urn:trusted:client", /*trusted=*/false);
  const auto sec = make_security(MessageSecurityMode::SignAndEncrypt);

  EXPECT_EQ(config.evaluate_roles(user, sec), 0u)
    << "Application criteria must require client_cert_trusted=true claim "
       "(Part 18 section 4.4.3 L786).";
}

// Gate 1 (signed channel) fails -> rule must not match even with a trusted
// cert.
TEST(ApplicationCriteriaGate, NoneChannelSuppressesArm)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role_with_app_criterion(1, "urn:trusted:client")));

  const auto user = make_user("urn:trusted:client", /*trusted=*/true);
  const auto sec = make_security(MessageSecurityMode::None);

  EXPECT_EQ(config.evaluate_roles(user, sec), 0u)
    << "Application criteria must require at least Sign channel mode "
       "(Part 18 section 4.4.3 L787).";
}

// Both gates clear -> rule matches and the Role is granted.
// @relation(SVR-SECADMIN-032, scope=function)
TEST(ApplicationCriteriaGate, SignedChannelPlusTrustedCertArmsRole)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role_with_app_criterion(2, "urn:trusted:client")));

  const auto user = make_user("urn:trusted:client", /*trusted=*/true);

  EXPECT_EQ(config.evaluate_roles(user, make_security(MessageSecurityMode::Sign)), uint64_t{1} << 2)
    << "Sign-mode + trusted cert must satisfy the Application criteria.";
  EXPECT_EQ(config.evaluate_roles(user, make_security(MessageSecurityMode::SignAndEncrypt)), uint64_t{1} << 2)
    << "SignAndEncrypt-mode + trusted cert must satisfy the Application criteria.";
}

// ============================================================================
// TrustedApplication criteria (Part 18 section 4.4.3, 1.05.04+ - IdentityCriteriaType
// value 9). Same two gates as Application (trusted cert + at least Sign), but
// the `criteria` field is NOT used: the rule matches ANY trusted application,
// regardless of its ApplicationUri.
// ============================================================================

namespace
{

RoleConfiguration::RoleDefinition role_with_trusted_app_criterion(uint8_t bit)
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::TrustedApplication;
  // No criteria value - TrustedApplication ignores it.
  RoleConfiguration::RoleDefinition def;
  def.roleId = custom_role(80 + bit);
  def.roleBit = bit;
  def.identities = {std::move(rule)};
  return def;
}

}  // namespace

// Gate 2 (trusted cert) fails -> rule must not match even on an encrypted channel.
// @relation(SVR-SECADMIN-032, scope=function)
TEST(TrustedApplicationCriteriaGate, UntrustedClientCertSuppressesArm)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role_with_trusted_app_criterion(0)));

  const auto user = make_user("urn:any:client", /*trusted=*/false);
  const auto sec = make_security(MessageSecurityMode::SignAndEncrypt);

  EXPECT_EQ(config.evaluate_roles(user, sec), 0u)
    << "TrustedApplication criteria must require client_cert_trusted=true (Part 18 section 4.4.3 L786).";
}

// Gate 1 (signed channel) fails -> rule must not match even with a trusted cert.
// @relation(SVR-SECADMIN-032, scope=function)
TEST(TrustedApplicationCriteriaGate, NoneChannelSuppressesArm)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role_with_trusted_app_criterion(1)));

  const auto user = make_user("urn:any:client", /*trusted=*/true);
  const auto sec = make_security(MessageSecurityMode::None);

  EXPECT_EQ(config.evaluate_roles(user, sec), 0u)
    << "TrustedApplication criteria must require at least Sign channel mode (Part 18 section 4.4.3 L787).";
}

// Both gates clear -> rule matches for ANY trusted application URI (the criteria
// field is ignored), which is what distinguishes it from the Application type.
TEST(TrustedApplicationCriteriaGate, AnyTrustedApplicationOnSignedChannelArmsRole)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role_with_trusted_app_criterion(2)));

  // Two unrelated application URIs - both must match because no URI comparison
  // is performed.
  const auto userA = make_user("urn:app:alpha", /*trusted=*/true);
  const auto userB = make_user("urn:app:bravo", /*trusted=*/true);

  EXPECT_EQ(config.evaluate_roles(userA, make_security(MessageSecurityMode::Sign)), uint64_t{1} << 2);
  EXPECT_EQ(
    config.evaluate_roles(userB, make_security(MessageSecurityMode::SignAndEncrypt)), uint64_t{1} << 2)
    << "TrustedApplication must match any trusted app, ignoring the ApplicationUri.";
}
