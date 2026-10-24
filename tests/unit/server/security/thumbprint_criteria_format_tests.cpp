// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for Part 18 section 4.4.3 L766-769 - Thumbprint criteria format
/// discipline.
///
/// Pins (SECADMIN-031):
///   * `add_identity_rule` stores Thumbprint criteria in the canonical
///     upper-case-hex-no-spaces shape regardless of input casing/spacing.
///   * `evaluate_roles` normalises the user-side `thumbprint` claim before
///     comparing - a mixed-case claim still matches a rule registered with
///     the canonical form.
///   * `add_identity_rule` rejects non-hex characters at config time with
///     `Bad_InvalidArgument` + a descriptive `ErrorDetail` carrying the
///     `server.tier1.authz.rbac.identity_rule.thumbprint.malformed` tag.

#include <gtest/gtest.h>

#include "ua_error_detail.h"
#include "ua_object_id.h"
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

RoleConfiguration::RoleDefinition make_role_with_bit(uint8_t bit)
{
  RoleConfiguration::RoleDefinition def;
  def.roleId = custom_role(40 + bit);
  def.roleBit = bit;
  return def;
}

IdentityMappingRuleType make_thumbprint_rule(std::string_view criteria)
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::Thumbprint;
  rule.criteria() = String{criteria};
  return rule;
}

UserIdentity make_x509_user(std::string thumbprintClaim)
{
  UserIdentity user;
  user.userId = "device";
  user.displayName = "device";
  user.kind = UserTokenKind::X509;
  user.claims["thumbprint"] = std::move(thumbprintClaim);
  return user;
}

EndpointSecurityContext make_security()
{
  EndpointSecurityContext sec;
  sec.messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  sec.securityPolicyId = SecurityPolicyId::Basic256Sha256;
  sec.endpointPolicyId = "L/SignAndEncrypt";
  return sec;
}

}  // namespace

// Spec L766-769: "the thumbprint shall be encoded as a hexadecimal string with
// upper case characters and without spaces." The stored rule must always
// carry that canonical form regardless of how the caller spelled it.
// @relation(SVR-SECADMIN-031, scope=function)
TEST(ThumbprintCriteriaFormat, EmittedRuleUsesUpperCaseHexNoSpaces)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(make_role_with_bit(4)));

  ASSERT_TRUE(config.add_identity_rule(custom_role(44), make_thumbprint_rule("ab cd 12 34")).is_good());
  auto stored = config.get_role(custom_role(44));
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(stored->identities.size(), 1u);
  EXPECT_EQ(static_cast<std::string_view>(stored->identities[0].criteria()), "ABCD1234")
    << "Stored Thumbprint criteria must be canonicalised to upper-case-hex-no-spaces.";
}

// `evaluate_roles` must normalise both sides of the compare so a client-side
// thumbprint claim that arrives in a non-canonical shape still matches the
// stored rule, AND a stored rule inserted in a non-canonical shape gets
// canonicalised at config time so it compares equal to canonical inbound
// claims. Both sides go through `normalise_thumbprint`.
// @relation(SVR-SECADMIN-031, scope=function)
TEST(ThumbprintCriteriaFormat, MatchingNormalisesBothSidesBeforeCompare)
{
  RoleConfiguration config;
  // Empty role first; insert the rule via `add_identity_rule` to exercise
  // the stored-side normaliser explicitly.
  ASSERT_TRUE(config.add_role(make_role_with_bit(5)));
  // Stored input is intentionally non-canonical (lower case + colon
  // separators). The normaliser must canonicalise it to "ABCDEF01"
  // before storage so it compares equal to canonical inbound claims.
  ASSERT_TRUE(config.add_identity_rule(custom_role(45), make_thumbprint_rule("ab:cd:ef:01")).is_good());
  // Confirm the stored side was canonicalised - this is the "stored-side
  // half" of the "both sides" assertion (without it the test would not
  // observe a regression in `add_identity_rule`'s normalisation step).
  auto stored = config.get_role(custom_role(45));
  ASSERT_TRUE(stored.has_value());
  ASSERT_EQ(stored->identities.size(), 1u);
  EXPECT_EQ(static_cast<std::string_view>(stored->identities[0].criteria()), "ABCDEF01")
    << "Stored side must canonicalise non-canonical input at add_identity_rule time.";

  const auto sec = make_security();

  // User-side claim in three different non-canonical shapes - all must
  // canonicalise to ABCDEF01 and match. This is the "user-side half".
  EXPECT_EQ(config.evaluate_roles(make_x509_user("ab:cd:ef:01"), sec), uint64_t{1} << 5)
    << "Colon-separated lower-case claim must canonicalise to ABCDEF01 and match.";
  EXPECT_EQ(config.evaluate_roles(make_x509_user("AbCdEf01"), sec), uint64_t{1} << 5)
    << "Mixed-case claim must canonicalise and match.";
  EXPECT_EQ(config.evaluate_roles(make_x509_user("AB-CD-EF-01"), sec), uint64_t{1} << 5)
    << "Dash-separated upper-case claim must canonicalise and match.";
  // Different thumbprint must not match.
  EXPECT_EQ(config.evaluate_roles(make_x509_user("12345678"), sec), 0u);
}

// Non-hex characters in the configured criteria must be rejected at
// `add_identity_rule` time with a `BadInvalidArgument` + the
// `...thumbprint.malformed` source tag.
// @relation(SVR-SECADMIN-031, scope=function)
TEST(ThumbprintCriteriaFormat, NonHexCharactersRejectedAtConfigTime)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(make_role_with_bit(6)));

  auto result = config.add_identity_rule(custom_role(46), make_thumbprint_rule("not-hex-string-zzz"));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadInvalidArgument);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_NE(result.error_detail()->source.find("thumbprint.malformed"), std::string::npos)
    << "ErrorDetail source must carry the thumbprint.malformed tag.";
  EXPECT_EQ(result.error_detail()->code, "IdentityRuleThumbprintMalformed");

  // Role must remain free of identity rules - rejection must not partially
  // mutate the configuration.
  auto stored = config.get_role(custom_role(46));
  ASSERT_TRUE(stored.has_value());
  EXPECT_TRUE(stored->identities.empty());
}
