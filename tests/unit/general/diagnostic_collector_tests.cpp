// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_diagnostic_bits.h"
#include "ua_diagnostic_collector.h"
#include "ua_diagnostic_policy.h"
#include "ua_diagnostic_security_context.h"
#include "ua_error_detail.h"
#include "ua_message_security_mode.h"
#include "ua_status_code_masking.h"
#include "ua_string_table_builder.h"

using namespace ua;
using namespace ua::server;

// --- StringTableBuilder ---

TEST(StringTableBuilder, EmptyStringReturnsMinusOne)
{
  StringTableBuilder builder;
  EXPECT_EQ(builder.intern(""), -1);
}

TEST(StringTableBuilder, InternsUniqueStrings)
{
  StringTableBuilder builder;
  EXPECT_EQ(builder.intern("alpha"), 0);
  EXPECT_EQ(builder.intern("beta"), 1);
  EXPECT_EQ(builder.intern("gamma"), 2);
  EXPECT_EQ(builder.size(), 3u);
}

TEST(StringTableBuilder, DeduplicatesStrings)
{
  StringTableBuilder builder;
  auto i1 = builder.intern("hello");
  auto i2 = builder.intern("world");
  auto i3 = builder.intern("hello");

  EXPECT_EQ(i1, 0);
  EXPECT_EQ(i2, 1);
  EXPECT_EQ(i3, 0);  // deduplicated
  EXPECT_EQ(builder.size(), 2u);
}

TEST(StringTableBuilder, BuildProducesArray)
{
  StringTableBuilder builder;
  builder.intern("foo");
  builder.intern("bar");

  auto table = builder.build();
  ASSERT_EQ(table.size(), 2u);
  EXPECT_EQ(std::string{table[0]}, "foo");
  EXPECT_EQ(std::string{table[1]}, "bar");
}

TEST(StringTableBuilder, EmptyBuildProducesEmptyArray)
{
  StringTableBuilder builder;
  auto table = builder.build();
  EXPECT_TRUE(table.empty());
}

// --- DiagnosticCollector (no security gating) ---

// Covers SVR-DIAG-011 (coverage-audit retag).
TEST(DiagnosticCollector, ZeroBitmaskIsNoop)
{
  DiagnosticCollector collector{0};

  EXPECT_FALSE(collector.wants_service_diagnostics());
  EXPECT_FALSE(collector.wants_operation_diagnostics());
  EXPECT_EQ(collector.effective_return_diagnostics(), 0u);

  // Add detail - should be silently dropped
  collector.set_service_detail(
    StatusCode{Status::BadInternalError, make_error_detail("Test", "Test error", "Source")});

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header);

  EXPECT_TRUE(!header.service_diagnostics().is_not_null());
  EXPECT_TRUE(header.string_table().empty());
  EXPECT_TRUE(itemDiags.empty());
}

TEST(DiagnosticCollector, ServiceLevelSymbolicId)
{
  DiagnosticCollector collector{diag::serviceSymbolicId};

  EXPECT_TRUE(collector.wants_service_diagnostics());
  EXPECT_FALSE(collector.wants_operation_diagnostics());

  collector.set_service_detail(StatusCode{
    Status::BadInternalError, make_error_detail("InternalError", "Something went wrong", "ReadService")});

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header);

  EXPECT_TRUE(header.service_diagnostics().is_not_null());
  EXPECT_TRUE(header.service_diagnostics().symbolic_id().has_value());
  EXPECT_TRUE(header.service_diagnostics().namespace_uri().has_value());

  // String table should contain the code and source
  EXPECT_GE(header.string_table().size(), 2u);
}

TEST(DiagnosticCollector, ServiceLevelLocalizedText)
{
  DiagnosticCollector collector{diag::serviceLocalizedText};

  collector.set_service_detail(
    StatusCode{Status::BadInternalError, make_error_detail("Code", "Human readable summary", "Source")});

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header);

  EXPECT_TRUE(header.service_diagnostics().localized_text().has_value());
}

TEST(DiagnosticCollector, ServiceLevelAdditionalInfo)
{
  DiagnosticCollector collector{diag::serviceAdditionalInfo};

  auto detail = make_error_detail("Code", "Summary", "Extended detail info", "Source");
  collector.set_service_detail(StatusCode{Status::BadInternalError, std::move(detail)});

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header);

  EXPECT_TRUE(header.service_diagnostics().additional_info().has_value());
  EXPECT_EQ(*header.service_diagnostics().additional_info(), "Extended detail info");
}

TEST(DiagnosticCollector, ServiceLevelInnerStatus)
{
  DiagnosticCollector collector{diag::serviceInnerStatus};

  auto detail = make_error_detail("Code", "Summary", "Source");
  detail->innerStatus = StatusCode{Status::BadTimeout}.value();
  collector.set_service_detail(StatusCode{Status::BadInternalError, std::move(detail)});

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header);

  EXPECT_TRUE(header.service_diagnostics().inner_status_code().has_value());
  EXPECT_EQ(header.service_diagnostics().inner_status_code()->as_status(), Status::BadTimeout);
}

// @relation(AC-SVR-METH-CALL-031-A-TYPED-HANDLERS-GOOD-SUBCODE-IS-ANSWERED-GOOD, scope=function)
TEST(DiagnosticCollector, AnInnerStatusThatIsNotBadIsSentAndPlainGoodIsNot)
{
  // A Method's Good subcode answered plain Good, and an Uncertain answer refused: the cause's code is sent,
  // with its information bits. A detail with no cause sends no inner status.
  for (const StatusCode inner :
    {StatusCode{Status::GoodClamped}, StatusCode{Status::UncertainLastUsableValue}})
  {
    SCOPED_TRACE(inner.value());
    DiagnosticCollector collector{diag::serviceInnerStatus};
    auto detail = make_error_detail("Code", "Summary", "Source");
    detail->innerStatus = inner.value() | 0x0400u;
    collector.set_service_detail(StatusCode{Status::Good, std::move(detail)});

    ResponseHeader header;
    collector.apply_to(header);

    ASSERT_TRUE(header.service_diagnostics().inner_status_code().has_value());
    EXPECT_EQ(header.service_diagnostics().inner_status_code()->value(), inner.value() | 0x0400u);
  }

  DiagnosticCollector collector{diag::serviceInnerStatus};
  collector.set_service_detail(
    StatusCode{Status::BadInternalError, make_error_detail("Code", "Summary", "Source")});
  ResponseHeader header;
  collector.apply_to(header);
  EXPECT_FALSE(header.service_diagnostics().inner_status_code().has_value());
}

// Covers SVR-DIAG-005, SVR-DIAG-009 (coverage-audit retag).
TEST(DiagnosticCollector, ServiceLevelInnerDiagnostics)
{
  DiagnosticCollector collector{diag::serviceInnerDiagnostics | diag::serviceSymbolicId};

  auto inner = make_error_detail("InnerCode", "Inner summary", "InnerSource");
  auto outer = make_error_detail("OuterCode", "Outer summary", "OuterSource");
  outer->cause = std::move(inner);
  outer->innerStatus = StatusCode{Status::BadTimeout}.value();

  collector.set_service_detail(StatusCode{Status::BadInternalError, std::move(outer)});

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header);

  ASSERT_NE(header.service_diagnostics().inner_diagnostic_info(), nullptr);
  EXPECT_TRUE(header.service_diagnostics().inner_diagnostic_info()->symbolic_id().has_value());
}

// Covers SVR-DIAG-010 (coverage-audit retag).
TEST(DiagnosticCollector, OperationLevelDiagnostics)
{
  DiagnosticCollector collector{diag::operationSymbolicId | diag::operationLocalizedText};

  EXPECT_TRUE(collector.wants_operation_diagnostics());

  // Three per-item StatusCodes - items 0 and 2 carry detail, item 1 does not.
  std::array<StatusCode, 3> statuses{
    StatusCode{Status::BadNodeIdUnknown, make_error_detail("NodeNotFound", "Node not found", "AddressSpace")},
    StatusCode{Status::Good},
    StatusCode{Status::BadTypeMismatch, make_error_detail("TypeMismatch", "Type mismatch", "ReadService")},
  };

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header, [&statuses](size_t i) { return statuses[i]; }, 3, itemDiags);

  ASSERT_EQ(itemDiags.size(), 3u);
  EXPECT_TRUE(itemDiags[0].is_not_null());  // has detail
  EXPECT_TRUE(!itemDiags[1].is_not_null());  // no detail
  EXPECT_TRUE(itemDiags[2].is_not_null());  // has detail
}

// @relation(AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY, scope=function)
TEST(DiagnosticCollector, NotificationItemsUseStickyPerItemMasksAndOneStringTable)
{
  DiagnosticCollector collector{diag::operationLevelMask};
  std::array<StatusCode, 3> statuses{
    StatusCode{Status::BadNodeIdUnknown, make_error_detail("NodeNotFound", "Node not found", "AddressSpace")},
    StatusCode{Status::BadTypeMismatch, make_error_detail("TypeMismatch", "Type mismatch", "ReadService")},
    StatusCode{Status::BadInternalError, make_error_detail("NotRequested", "Must stay hidden", "Internal")},
  };
  std::array<uint32_t, 3> masks{diag::operationSymbolicId, diag::operationLocalizedText, 0u};

  Array<String> stringTable;
  Array<DiagnosticInfo> itemDiagnostics;
  collector.apply_to_notification_items(
    stringTable,
    [&statuses](size_t index) { return statuses[index]; },
    [&masks](size_t index) { return masks[index]; },
    statuses.size(),
    itemDiagnostics);

  ASSERT_EQ(itemDiagnostics.size(), statuses.size());
  ASSERT_TRUE(itemDiagnostics[0].symbolic_id().has_value());
  EXPECT_FALSE(itemDiagnostics[0].localized_text().has_value());
  EXPECT_FALSE(itemDiagnostics[1].symbolic_id().has_value());
  ASSERT_TRUE(itemDiagnostics[1].localized_text().has_value());
  EXPECT_TRUE(itemDiagnostics[2].is_null());

  const auto symbolicIndex = static_cast<size_t>(*itemDiagnostics[0].symbolic_id());
  const auto localizedIndex = static_cast<size_t>(*itemDiagnostics[1].localized_text());
  ASSERT_LT(symbolicIndex, stringTable.size());
  ASSERT_LT(localizedIndex, stringTable.size());
  EXPECT_EQ(std::string{stringTable[symbolicIndex]}, "NodeNotFound");
  EXPECT_EQ(std::string{stringTable[localizedIndex]}, "Type mismatch");
}

// @relation(AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY, scope=function)
TEST(DiagnosticCollector, NotificationItemsWithZeroMasksProduceNoOutput)
{
  DiagnosticCollector collector{diag::operationLevelMask};
  std::array<StatusCode, 1> statuses{
    StatusCode{Status::BadInternalError, make_error_detail("Hidden", "Hidden diagnostic", "Internal")}};
  std::array<uint32_t, 1> masks{0u};

  Array<String> stringTable;
  Array<DiagnosticInfo> itemDiagnostics;
  collector.apply_to_notification_items(
    stringTable,
    [&statuses](size_t index) { return statuses[index]; },
    [&masks](size_t index) { return masks[index]; },
    statuses.size(),
    itemDiagnostics);

  EXPECT_TRUE(stringTable.empty());
  EXPECT_TRUE(itemDiagnostics.empty());
}

TEST(DiagnosticCollector, SharedStringTable)
{
  // Service and operation diagnostics share the same string table
  DiagnosticCollector collector{diag::serviceSymbolicId | diag::operationSymbolicId};

  collector.set_service_detail(
    StatusCode{Status::BadInternalError, make_error_detail("SharedCode", "Summary", "Source")});

  std::array<StatusCode, 1> statuses{
    StatusCode{Status::BadInternalError, make_error_detail("SharedCode", "Summary", "Source")}};

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header, [&statuses](size_t i) { return statuses[i]; }, 1, itemDiags);

  // "SharedCode" and "Source" should be deduplicated in the string table
  // Service and operation diagnostics should reference the same indices
  EXPECT_EQ(header.service_diagnostics().symbolic_id(), itemDiags[0].symbolic_id());
  EXPECT_EQ(header.service_diagnostics().namespace_uri(), itemDiags[0].namespace_uri());
}

TEST(DiagnosticCollector, NullDetailIsIgnored)
{
  DiagnosticCollector collector{diag::serviceSymbolicId};

  collector.set_service_detail(StatusCode{Status::BadInternalError});

  ResponseHeader header;
  Array<DiagnosticInfo> itemDiags;
  collector.apply_to(header);

  EXPECT_TRUE(!header.service_diagnostics().is_not_null());
}

// --- Security gating ---

namespace
{

DiagnosticSecurityContext make_context(
  bool authenticated, bool secured, ServerConfig::DiagnosticPolicy::Level level, bool maskPreAuth = true)
{
  DiagnosticSecurityContext ctx;
  ctx.authenticated = authenticated;
  ctx.securedChannel = secured;
  ctx.effectiveLevel = level;
  ctx.maskPreAuthErrors = maskPreAuth;
  return ctx;
}

}  // namespace

using Level = ServerConfig::DiagnosticPolicy::Level;

TEST(DiagnosticCollectorSecurity, NoneChannelSuppressesAll)
{
  auto ctx = make_context(true, false, Level::Full);
  DiagnosticCollector collector{0xFFFF, ctx};

  EXPECT_EQ(collector.effective_return_diagnostics(), 0u);
  EXPECT_FALSE(collector.wants_service_diagnostics());
  EXPECT_FALSE(collector.wants_operation_diagnostics());
}

// Covers SVR-DIAG-015 (coverage-audit retag).
TEST(DiagnosticCollectorSecurity, PreAuthSuppressesAll)
{
  auto ctx = make_context(false, true, Level::Full);
  DiagnosticCollector collector{0xFFFF, ctx};

  EXPECT_EQ(collector.effective_return_diagnostics(), 0u);
  EXPECT_TRUE(collector.should_mask_pre_auth_errors());
}

TEST(DiagnosticCollectorSecurity, PostAuthNonePolicySuppressesAll)
{
  auto ctx = make_context(true, true, Level::None);
  DiagnosticCollector collector{0xFFFF, ctx};

  EXPECT_EQ(collector.effective_return_diagnostics(), 0u);
}

// @relation(AC-SVR-MI-GEN-093-RETURNDIAGNOSTICS-STICKY, scope=function)
TEST(DiagnosticCollectorSecurity, NotificationItemsRespectSessionDiagnosticPolicy)
{
  DiagnosticCollector collector{diag::operationLevelMask, make_context(true, true, Level::None)};
  std::array<StatusCode, 1> statuses{
    StatusCode{Status::BadInternalError, make_error_detail("Hidden", "Hidden diagnostic", "Internal")}};
  std::array<uint32_t, 1> masks{diag::operationLevelMask};

  Array<String> stringTable;
  Array<DiagnosticInfo> itemDiagnostics;
  collector.apply_to_notification_items(
    stringTable,
    [&statuses](size_t index) { return statuses[index]; },
    [&masks](size_t index) { return masks[index]; },
    statuses.size(),
    itemDiagnostics);

  EXPECT_TRUE(stringTable.empty());
  EXPECT_TRUE(itemDiagnostics.empty());
}

TEST(DiagnosticCollectorSecurity, PostAuthSummaryFiltersBitmask)
{
  auto ctx = make_context(true, true, Level::Summary);

  // Client requests everything
  DiagnosticCollector collector{0xFFFF, ctx};

  // Only symbolicId and localizedText should be allowed
  constexpr uint32_t expectedMask = diag::serviceSymbolicId | diag::serviceLocalizedText |
                                    diag::operationSymbolicId | diag::operationLocalizedText;
  EXPECT_EQ(collector.effective_return_diagnostics(), expectedMask);

  // No masking post-auth
  EXPECT_FALSE(collector.should_mask_pre_auth_errors());
}

TEST(DiagnosticCollectorSecurity, PostAuthFullPassesBitmask)
{
  auto ctx = make_context(true, true, Level::Full);
  DiagnosticCollector collector{0x01FF, ctx};

  EXPECT_EQ(collector.effective_return_diagnostics(), 0x01FFu);
}

// Behavioural check that DiagnosticPolicy gates the NEW structured context, not
// just the bitmask: Summary masks out the AdditionalInfo bit (0x04) so context
// never reaches the wire; Full emits it as the marker-tagged JSON.
TEST(DiagnosticCollectorSecurity, SummarySuppressesStructuredContextFullEmitsIt)
{
  auto detail = std::make_shared<ErrorDetail>();
  detail->code = "WriteFailed";
  detail->summary = "write rejected";
  detail->source = "server.services.write";
  detail->context.push_back(NamedValue{"node.id", "ns=2;i=5"});

  {
    DiagnosticCollector collector{0xFFFF, make_context(true, true, Level::Summary)};
    collector.set_service_detail(StatusCode{Status::BadInternalError, detail});
    ResponseHeader header;
    collector.apply_to(header);
    EXPECT_FALSE(header.service_diagnostics().additional_info().has_value());
  }
  {
    DiagnosticCollector collector{0xFFFF, make_context(true, true, Level::Full)};
    collector.set_service_detail(StatusCode{Status::BadInternalError, detail});
    ResponseHeader header;
    collector.apply_to(header);
    ASSERT_TRUE(header.service_diagnostics().additional_info().has_value());
    EXPECT_NE(header.service_diagnostics().additional_info()->find("$uactx"), std::string::npos);
  }
}

// --- Status code masking ---

// Covers SVR-SECADMIN-006 (coverage-audit retag).
TEST(StatusCodeMasking, CertificateErrorsMasked)
{
  using namespace ua::server::detail;

  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::BadCertificateInvalid}).as_status(),
    Status::BadSecurityChecksFailed);
  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::BadCertificateUntrusted}).as_status(),
    Status::BadSecurityChecksFailed);
  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::BadCertificateRevoked}).as_status(),
    Status::BadSecurityChecksFailed);
  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::BadCertificateChainIncomplete}).as_status(),
    Status::BadSecurityChecksFailed);
}

// Table 106's Validity Period, Host Name, URI and Certificate Usage rows do not tell the Server to report
// Bad_SecurityChecksFailed, and Table 12 lists their codes among the OpenSecureChannel results: the specific
// code reaches the client (the CTT's Security Certificate Validation 007, 008 and 029).
// Covers SVR-SECADMIN-006.
TEST(StatusCodeMasking, CertificateErrorsTable106DoesNotMaskPassThrough)
{
  using namespace ua::server::detail;

  for (const auto status : {Status::BadCertificateTimeInvalid,
         Status::BadCertificateIssuerTimeInvalid,
         Status::BadCertificateHostNameInvalid,
         Status::BadCertificateUriInvalid,
         Status::BadCertificateUseNotAllowed,
         Status::BadCertificateIssuerUseNotAllowed})
  {
    EXPECT_EQ(mask_pre_auth_status(StatusCode{status}).as_status(), status)
      << "0x" << std::hex << StatusCode{status}.as_uint32();
  }
  for (const auto status : {Status::BadCertificateRevocationUnknown,
         Status::BadCertificateIssuerRevoked,
         Status::BadCertificatePolicyCheckFailed})
  {
    EXPECT_EQ(mask_pre_auth_status(StatusCode{status}).as_status(), Status::BadSecurityChecksFailed)
      << "0x" << std::hex << StatusCode{status}.as_uint32();
  }
}

// Covers SVR-IDENT-005 (coverage-audit retag).
TEST(StatusCodeMasking, IdentityTokenErrorsMasked)
{
  using namespace ua::server::detail;

  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::BadIdentityTokenInvalid}).as_status(),
    Status::BadIdentityTokenRejected);
}

TEST(StatusCodeMasking, NonSecurityCodePassesThrough)
{
  using namespace ua::server::detail;

  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::BadNodeIdUnknown}).as_status(), Status::BadNodeIdUnknown);
  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::BadTimeout}).as_status(), Status::BadTimeout);
  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::Good}).as_status(), Status::Good);
}

TEST(StatusCodeMasking, NonceAndSignatureErrorsMasked)
{
  using namespace ua::server::detail;

  EXPECT_EQ(
    mask_pre_auth_status(StatusCode{Status::BadNonceInvalid}).as_status(), Status::BadSecurityChecksFailed);
  EXPECT_EQ(mask_pre_auth_status(StatusCode{Status::BadApplicationSignatureInvalid}).as_status(),
    Status::BadSecurityChecksFailed);
}

// --- Diagnostic level resolution ---

TEST(DiagnosticLevelResolver, NoneMaxLevelAlwaysReturnsNone)
{
  ServerConfig::DiagnosticPolicy policy;
  policy.maxLevel = Level::None;

  UserIdentity user;
  user.claims["diagnostics:full"] = "true";

  EXPECT_EQ(ua::server::detail::resolve_diagnostic_level(policy, user), Level::None);
}

TEST(DiagnosticLevelResolver, FullClaimWithFullCeiling)
{
  ServerConfig::DiagnosticPolicy policy;
  policy.maxLevel = Level::Full;
  policy.defaultLevel = Level::None;

  UserIdentity user;
  user.claims["diagnostics:full"] = "true";

  EXPECT_EQ(ua::server::detail::resolve_diagnostic_level(policy, user), Level::Full);
}

TEST(DiagnosticLevelResolver, FullClaimCappedBySummaryCeiling)
{
  ServerConfig::DiagnosticPolicy policy;
  policy.maxLevel = Level::Summary;
  policy.defaultLevel = Level::None;

  UserIdentity user;
  user.claims["diagnostics:full"] = "true";

  // Full claim but ceiling is Summary - should get Summary (via the summary claim check)
  // Actually no - user has "diagnostics:full" not "diagnostics:summary"
  // and maxLevel is Summary, so the full check fails. Falls through to summary check
  // which also fails (no summary claim). Falls to default.
  EXPECT_EQ(ua::server::detail::resolve_diagnostic_level(policy, user), Level::None);
}

TEST(DiagnosticLevelResolver, SummaryClaimWithFullCeiling)
{
  ServerConfig::DiagnosticPolicy policy;
  policy.maxLevel = Level::Full;
  policy.defaultLevel = Level::None;

  UserIdentity user;
  user.claims["diagnostics:summary"] = "true";

  EXPECT_EQ(ua::server::detail::resolve_diagnostic_level(policy, user), Level::Summary);
}

// Owner decision 2026-10-03 (D-b): a session holding SecurityAdmin counts as claiming DiagnosticsFull, so a
// refused TrustList update names its invalid Certificate (OPC 10000-12 7.8.2.3) with the default policy;
// maxLevel still caps it, and None still turns diagnostics off. Falsifiable: without the role rule the
// default level (None) applies.
// @relation(AC-COMP-CORE-CERTIFICATE-VALIDATION-MATRIX-129-TRUST-LIST-LIVE-COMPLETENESS, scope=function)
TEST(DiagnosticLevelResolver, SecurityAdminResolvesFullCappedByTheCeiling)
{
  ServerConfig::DiagnosticPolicy policy;
  policy.defaultLevel = Level::None;
  UserIdentity user;

  policy.maxLevel = Level::Full;
  EXPECT_EQ(
    ua::server::detail::resolve_diagnostic_level(policy, user, /*holdsSecurityAdmin=*/true), Level::Full);
  EXPECT_EQ(
    ua::server::detail::resolve_diagnostic_level(policy, user, /*holdsSecurityAdmin=*/false), Level::None)
    << "control: without the Role the default applies";

  policy.maxLevel = Level::Summary;
  EXPECT_EQ(
    ua::server::detail::resolve_diagnostic_level(policy, user, /*holdsSecurityAdmin=*/true), Level::Summary);

  policy.maxLevel = Level::None;
  EXPECT_EQ(
    ua::server::detail::resolve_diagnostic_level(policy, user, /*holdsSecurityAdmin=*/true), Level::None);
}

TEST(DiagnosticLevelResolver, NoClaimsReturnsDefault)
{
  ServerConfig::DiagnosticPolicy policy;
  policy.maxLevel = Level::Full;
  policy.defaultLevel = Level::Summary;

  UserIdentity user;

  EXPECT_EQ(ua::server::detail::resolve_diagnostic_level(policy, user), Level::Summary);
}

// --- make_diagnostic_security_context ---

TEST(MakeDiagnosticSecurityContext, SecuredChannelWithFullPolicy)
{
  EndpointSecurityContext endpoint;
  endpoint.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;

  UserIdentity user;
  user.claims["diagnostics:full"] = "true";

  ServerConfig::DiagnosticPolicy policy;
  policy.maxLevel = Level::Full;
  policy.defaultLevel = Level::None;

  auto ctx = ua::server::detail::make_diagnostic_security_context(endpoint, user, policy);

  EXPECT_TRUE(ctx.authenticated);
  EXPECT_TRUE(ctx.securedChannel);
  EXPECT_EQ(ctx.effectiveLevel, Level::Full);
  EXPECT_FALSE(ctx.maskPreAuthErrors);
}

TEST(MakeDiagnosticSecurityContext, NoneSecurityModeIsUnsecured)
{
  EndpointSecurityContext endpoint;
  endpoint.messageSecurityMode = ua::MessageSecurityMode::None;

  UserIdentity user;

  ServerConfig::DiagnosticPolicy policy;
  policy.maxLevel = Level::Full;
  policy.defaultLevel = Level::Full;

  auto ctx = ua::server::detail::make_diagnostic_security_context(endpoint, user, policy);

  EXPECT_TRUE(ctx.authenticated);
  EXPECT_FALSE(ctx.securedChannel);

  // Even though policy is Full, the DiagnosticCollector will suppress
  // everything because securedChannel is false.
  DiagnosticCollector collector{0xFFFF, ctx};
  EXPECT_EQ(collector.effective_return_diagnostics(), 0u);
}

TEST(MakeDiagnosticSecurityContext, SignModeIsSecured)
{
  EndpointSecurityContext endpoint;
  endpoint.messageSecurityMode = ua::MessageSecurityMode::Sign;

  UserIdentity user;

  ServerConfig::DiagnosticPolicy policy;
  policy.maxLevel = Level::Summary;
  policy.defaultLevel = Level::Summary;

  auto ctx = ua::server::detail::make_diagnostic_security_context(endpoint, user, policy);

  EXPECT_TRUE(ctx.securedChannel);
  EXPECT_EQ(ctx.effectiveLevel, Level::Summary);
}
