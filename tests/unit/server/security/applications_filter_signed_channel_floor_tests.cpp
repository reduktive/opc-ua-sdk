// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for Part 18 section 4.4.1 L665-671 - Applications-filtered Role
/// signed-channel floor.
///
/// Pins (SECADMIN-029): a Role whose `Applications` Property is non-empty
/// (regardless of `ApplicationsExclude`) participates in Application
/// authentication and is therefore only valid on a Session whose channel is
/// at least signed. `evaluate_roles` skips the Role outright when the
/// `MessageSecurityMode` is `None`, so no caller on an insecure channel can
/// receive the Role.

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

UserIdentity make_user_with_app(std::string appUri)
{
  UserIdentity user;
  user.userId = "alice";
  user.kind = UserTokenKind::UserName;
  user.claims["app:uri"] = std::move(appUri);
  return user;
}

EndpointSecurityContext make_security(MessageSecurityMode mode)
{
  EndpointSecurityContext sec;
  sec.messageSecurityMode = mode;
  sec.securityPolicyId =
    mode == MessageSecurityMode::None ? SecurityPolicyId::None : SecurityPolicyId::Basic256Sha256;
  sec.endpointPolicyId = "L/Test";
  if (mode != MessageSecurityMode::None)
    sec.clientApplicationUri = "urn:trusted";
  return sec;
}

IdentityMappingRuleType username_rule(std::string user)
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::UserName;
  rule.criteria() = String{std::move(user)};
  return rule;
}

RoleConfiguration::RoleDefinition role_with_app_filter(uint8_t bit, std::vector<String> apps, bool exclude)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = custom_role(60 + bit);
  def.roleBit = bit;
  def.applications = std::move(apps);
  def.applicationsExclude = exclude;
  def.identities = {username_rule("alice")};
  return def;
}

}  // namespace

// Even when the caller's app URI matches the include list, a `None`-mode
// channel must not satisfy an Applications-filtered Role.
// @relation(SVR-SECADMIN-029, scope=function)
TEST(ApplicationsFilterSignedChannelFloor, ApplicationsConfiguredRejectsNoneChannel)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role_with_app_filter(2, {String{"urn:trusted"}}, /*exclude=*/false)));

  const auto user = make_user_with_app("urn:trusted");
  const auto sec = make_security(MessageSecurityMode::None);

  EXPECT_EQ(config.evaluate_roles(user, sec), 0u)
    << "Applications-filtered Role must be skipped on a None-mode channel "
       "(Part 18 section 4.4.1 L665-671).";
}

// A signed channel (Sign or SignAndEncrypt) clears the floor; the Role
// participates as before.
// @relation(SVR-SECADMIN-029, scope=function)
TEST(ApplicationsFilterSignedChannelFloor, ApplicationsConfiguredAcceptsSignedChannel)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(role_with_app_filter(3, {String{"urn:trusted"}}, /*exclude=*/false)));

  const auto user = make_user_with_app("urn:trusted");
  EXPECT_EQ(config.evaluate_roles(user, make_security(MessageSecurityMode::Sign)), uint64_t{1} << 3)
    << "Sign-mode channel must satisfy the Applications-filter floor.";
  EXPECT_EQ(config.evaluate_roles(user, make_security(MessageSecurityMode::SignAndEncrypt)), uint64_t{1} << 3)
    << "SignAndEncrypt-mode channel must satisfy the Applications-filter floor.";
}
