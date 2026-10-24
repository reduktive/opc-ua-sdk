// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Unit tests for Part 18 section 4.4.3 L793-808 + Table 8 - X509Subject criteria
/// canonicalisation.
///
/// Pins (SECADMIN-033):
///   * `add_identity_rule` stores X509Subject criteria in the canonical
///     Table-8-ordered token sequence regardless of input ordering.
///   * Repeated attribute names preserve their input order (per spec L805-807:
///     "the entries with the same name are entered in the order they appear
///     in the Certificate").
///   * Non-Table-8 attributes are silently dropped at config time
///     (spec L807-808: "Names not included in Table 8 are ignored").
///   * Values containing a `"` character are rejected with
///     `Bad_InvalidArgument` (spec L796 + L801: values are always enclosed
///     in double quotes, so an embedded `"` is unparseable).

#include <gtest/gtest.h>

#include "ua_error_detail.h"
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
  def.roleId = custom_role(50 + bit);
  def.roleBit = bit;
  return def;
}

IdentityMappingRuleType make_x509_rule(std::string_view criteria)
{
  IdentityMappingRuleType rule;
  rule.criteria_type() = IdentityCriteriaType::X509Subject;
  rule.criteria() = String{criteria};
  return rule;
}

std::string get_stored_criteria(const RoleConfiguration& config, const NodeId& roleId)
{
  auto stored = config.get_role(roleId);
  if (!stored.has_value() || stored->identities.empty())
    return {};
  return std::string{static_cast<std::string_view>(stored->identities[0].criteria())};
}

}  // namespace

// Spec L797-798: "The order shall be by the order shown in Table 8 with the
// lowest number first." A caller can supply tokens in any order; the stored
// rule must reflect the canonical CN, O, OU, DC, L, S, C, dnQualifier,
// serialNumber sequence.
// @relation(SVR-SECADMIN-033, scope=function)
TEST(X509SubjectCriteriaFormat, CanonicaliserProducesTable8OrderedTokens)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(make_role_with_bit(0)));

  // Input intentionally out of order - O before CN, OU after L.
  ASSERT_TRUE(
    config.add_identity_rule(custom_role(50), make_x509_rule(R"(O="Acme"/CN="Alice"/L="Berlin"/OU="Eng")"))
      .is_good());

  // Expected canonical order: CN(1), O(2), OU(3), L(5).
  EXPECT_EQ(get_stored_criteria(config, custom_role(50)), R"(CN="Alice"/O="Acme"/OU="Eng"/L="Berlin")")
    << "Stored X509Subject criteria must be Table-8 ordered.";
}

// Spec L805-807: "If one name is used multiple times in the certificate, the
// name is also repeated in the criteria. The entries with the same name are
// entered in the order they appear in the Certificate." Stable sort by
// Table-8 column preserves the input order within a name.
// @relation(SVR-SECADMIN-033, scope=function)
TEST(X509SubjectCriteriaFormat, RepeatedAttributesPreserveCertOrder)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(make_role_with_bit(1)));

  // Two OUs, in a known input order, interleaved with CN/O.
  ASSERT_TRUE(
    config.add_identity_rule(custom_role(51), make_x509_rule(R"(OU="Eng"/CN="Alice"/OU="Security"/O="Acme")"))
      .is_good());

  // Expected: CN, O, then both OUs in their original input order.
  EXPECT_EQ(get_stored_criteria(config, custom_role(51)), R"(CN="Alice"/O="Acme"/OU="Eng"/OU="Security")")
    << "Repeated OU attributes must keep their original (input) order in the canonical form.";
}

// Part 18 section 4.4.3 requires each name supplied in the criteria string to
// be a Table-8 entry. Its later "ignored" rule applies to extra names in the
// Certificate being matched, not to an invalid administrator-supplied rule.
// @relation(SVR-SECADMIN-033, scope=function)
TEST(X509SubjectCriteriaFormat, NonTable8AttributesRejectedAtConfigTime)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(make_role_with_bit(2)));

  auto result =
    config.add_identity_rule(custom_role(52), make_x509_rule(R"(CN="Alice"/E="alice@acme.com"/O="Acme")"));

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadInvalidArgument);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "IdentityRuleSubjectMalformed");
  EXPECT_NE(result.error_detail()->source.find("x509_subject.malformed"), std::string::npos);
  EXPECT_TRUE(config.get_role(custom_role(52))->identities.empty())
    << "an invalid attribute must reject the rule atomically, not store a broader rule";
}

// Spec L796 + L801: values are always double-quoted, and the value "may be
// any printable character except for '\"'". An embedded `"` is therefore
// ambiguous and must be rejected at config time.
// @relation(SVR-SECADMIN-033, scope=function)
TEST(X509SubjectCriteriaFormat, DoubleQuoteInValueRejectedAtConfigTime)
{
  RoleConfiguration config;
  ASSERT_TRUE(config.add_role(make_role_with_bit(3)));

  // Embedded double quote: `Alice"injected"`. The canonicaliser sees this
  // as `CN="Alice"` followed by garbage tokens - it must reject.
  auto result = config.add_identity_rule(custom_role(53), make_x509_rule(R"(CN="Alice"injected"/O="Acme")"));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadInvalidArgument);
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_NE(result.error_detail()->source.find("x509_subject.malformed"), std::string::npos)
    << "ErrorDetail source must carry the x509_subject.malformed tag.";
  EXPECT_EQ(result.error_detail()->code, "IdentityRuleSubjectMalformed");

  // No rule must have been stored (atomic reject).
  auto stored = config.get_role(custom_role(53));
  ASSERT_TRUE(stored.has_value());
  EXPECT_TRUE(stored->identities.empty());
}
