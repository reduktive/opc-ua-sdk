// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_numeric_range_validation.h"

#include "ua_error_detail.h"
#include "ua_status.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>

namespace
{

using ua::client::detail::NumericRangeUse;
using ua::client::detail::validate_client_numeric_range;

const ua::NodeId node{2, 5000};

// The local check serves both services; each arm below runs for both.
constexpr NumericRangeUse bothUses[] = {NumericRangeUse::Read, NumericRangeUse::Write};

const char* use_name(NumericRangeUse use)
{
  return use == NumericRangeUse::Read ? "the Read" : "the Write";
}

// @verifies AC-CL-ADDRSP-006-NUMERICRANGE
// @verifies AC-CL-ATTR-008-NUMERICRANGE-SYNTAX
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, CL-ATTR-008, scope=function)
TEST(ClientNumericRangeValidation, RejectsEqualAndDescendingBounds)
{
  for (const NumericRangeUse use : bothUses)
  {
    for (const ua::NumericRange range : {ua::NumericRange{"5:5"}, ua::NumericRange{"7:5"}})
    {
      auto result = validate_client_numeric_range(node, range, 1, use);
      ASSERT_TRUE(result.is_bad()) << use_name(use);
      EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadIndexRangeInvalid}) << use_name(use);
      ASSERT_NE(result.shared_detail(), nullptr) << use_name(use);
      EXPECT_EQ(result.shared_detail()->code, "NumericRangeSyntaxInvalid") << use_name(use);
    }
  }
}

// @verifies AC-CL-ADDRSP-006-NUMERICRANGE
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, scope=function)
TEST(ClientNumericRangeValidation, RejectsWhitespaceAndOtherNonGrammarCharacters)
{
  for (const NumericRangeUse use : bothUses)
  {
    auto result = validate_client_numeric_range(node, ua::NumericRange{"5 :7"}, 1, use);
    ASSERT_TRUE(result.is_bad()) << use_name(use);
    EXPECT_EQ(result.status_code(), ua::StatusCode{ua::Status::BadIndexRangeInvalid}) << use_name(use);
    ASSERT_NE(result.shared_detail(), nullptr) << use_name(use);
    EXPECT_EQ(result.shared_detail()->code, "NumericRangeSyntaxInvalid") << use_name(use);
  }
}

// Part 4 section 7.27: a range with fewer dimensions than a fixed rank is answered as the server answers it
// (DL-7 (b)): Bad_IndexRangeNoData for a Read, a request with a valid syntax that selects nothing, and
// Bad_IndexRangeInvalid for a Write (NR-42 A-14). Both name the dimension count and the Node.
// @verifies AC-CL-ADDRSP-006-NUMERICRANGE
// @relation(AC-CL-ADDRSP-006-NUMERICRANGE, scope=function)
// @relation(AC-CL-ATTR-009-NUMERICRANGE-ALLDIMS, scope=function)
TEST(ClientNumericRangeValidation, RequiresEveryFixedRankDimension)
{
  auto read = validate_client_numeric_range(node, ua::NumericRange{"0:1"}, 2, NumericRangeUse::Read);
  ASSERT_TRUE(read.is_bad());
  EXPECT_EQ(read.status_code().as_status(), ua::Status::BadIndexRangeNoData);
  ASSERT_NE(read.shared_detail(), nullptr);
  EXPECT_EQ(read.shared_detail()->code, "NumericRangeDimensionCountMismatch");
  EXPECT_NE(ua::to_string(*read.shared_detail()).find("ns=2;i=5000"), std::string::npos);

  auto write = validate_client_numeric_range(node, ua::NumericRange{"0:1"}, 2, NumericRangeUse::Write);
  ASSERT_TRUE(write.is_bad());
  EXPECT_EQ(write.status_code().as_status(), ua::Status::BadIndexRangeInvalid);
  ASSERT_NE(write.shared_detail(), nullptr);
  EXPECT_EQ(write.shared_detail()->code, "NumericRangeDimensionCountMismatch");
  EXPECT_NE(ua::to_string(*write.shared_detail()).find("ns=2;i=5000"), std::string::npos);
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
TEST(ClientNumericRangeValidation, AcceptsValidCompleteRangeAndEmptyWholeValue)
{
  for (const NumericRangeUse use : bothUses)
  {
    auto complete = validate_client_numeric_range(node, ua::NumericRange{"0:1,2:3"}, 2, use);
    ASSERT_TRUE(complete.is_good()) << use_name(use);
    EXPECT_EQ(complete.value().dimension_count(), 2u) << use_name(use);
    EXPECT_TRUE(validate_client_numeric_range(node, ua::NumericRange{}, 2, use).is_good()) << use_name(use);
  }
}

// @verifies CL-ATTR-011
// @relation(CL-ATTR-011, scope=function)
TEST(ClientNumericRangeValidation, AllowsTrailingElementSubstringDimension)
{
  auto result = validate_client_numeric_range(node, ua::NumericRange{"2,3:7"}, 1, NumericRangeUse::Write);

  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().dimension_count(), 2u);
}

// @verifies CL-ADDRSP-006
// @relation(CL-ADDRSP-006, scope=function)
// @relation(AC-CL-ATTR-009-NUMERICRANGE-ALLDIMS, scope=function)
TEST(ClientNumericRangeValidation, LeavesFlexibleRankDimensionalityToServer)
{
  for (const NumericRangeUse use : bothUses)
  {
    for (const std::int32_t rank : {-3, -2, -1, 0})
    {
      EXPECT_TRUE(validate_client_numeric_range(node, ua::NumericRange{"0:1"}, rank, use).is_good())
        << use_name(use) << " with the ValueRank " << rank;
    }
    EXPECT_TRUE(validate_client_numeric_range(node, ua::NumericRange{"0:1"}, std::nullopt, use).is_good())
      << use_name(use) << " with no ValueRank";
  }
}

// Part 3 section 8.2.4 Table 23: besides the canonical null (IdType Numeric, ns 0, identifier 0), a String
// NodeId with an empty identifier, an all-zero Guid and an empty ByteString at namespace 0 are all null
// NodeIds. The obvious implementation compares against the canonical null only, so the alternative encodings
// fall through as ordinary NodeIds and a service that should apply its defined null behaviour instead reports
// an unresolvable node. Each form is therefore checked to still carry its own IdType, so recognition cannot
// come from having silently built the canonical form four times; the near-null and non-zero-namespace forms
// pin the other side, so a predicate that simply answered true could not pass.
// @verifies AC-CL-ADDRSP-003-NULL-NODEID
TEST(ClientNumericRangeValidation, NullNodeIdRecognisedInCanonicalAndAlternativeEncodings)
{
  const ua::NodeId canonical{std::uint16_t{0}, std::uint32_t{0}};
  const ua::NodeId emptyString{std::uint16_t{0}, ua::string_view{""}};
  const ua::NodeId defaultGuid{std::uint16_t{0}, ua::Guid{}};
  const ua::NodeId zeroGuid{std::uint16_t{0}, ua::Guid::parse("00000000-0000-0000-0000-000000000000")};
  const ua::NodeId emptyOpaque{std::uint16_t{0}, ua::ByteString{}};

  // Each stimulus really is the encoding it claims to be, so a true verdict below cannot come from the
  // canonical numeric form having been constructed under another name.
  EXPECT_EQ(canonical.id_type(), ua::IdType::Numeric);
  EXPECT_EQ(emptyString.id_type(), ua::IdType::String);
  EXPECT_EQ(defaultGuid.id_type(), ua::IdType::Guid);
  EXPECT_EQ(zeroGuid.id_type(), ua::IdType::Guid);
  EXPECT_EQ(emptyOpaque.id_type(), ua::IdType::Opaque);

  EXPECT_TRUE(canonical.is_null());
  EXPECT_TRUE(emptyString.is_null());
  EXPECT_TRUE(defaultGuid.is_null());
  EXPECT_TRUE(zeroGuid.is_null());
  EXPECT_TRUE(emptyOpaque.is_null());

  // A NodeId that merely resembles a null one is a real NodeId and must resolve normally.
  EXPECT_FALSE((ua::NodeId{std::uint16_t{0}, std::uint32_t{1}}.is_null()));
  EXPECT_FALSE((ua::NodeId{std::uint16_t{0}, ua::string_view{"0"}}.is_null()));
  EXPECT_FALSE(
    (ua::NodeId{std::uint16_t{0}, ua::Guid::parse("00000000-0000-0000-0000-000000000001")}.is_null()));
  EXPECT_FALSE((ua::NodeId{std::uint16_t{0}, ua::ByteString{std::uint8_t{0}}}.is_null()));

  // Table 23 scopes every null form to NamespaceIndex 0; the same identifiers elsewhere address that
  // namespace and must not be short-circuited as null.
  EXPECT_FALSE((ua::NodeId{std::uint16_t{2}, std::uint32_t{0}}.is_null()));
  EXPECT_FALSE((ua::NodeId{std::uint16_t{2}, ua::string_view{""}}.is_null()));
  EXPECT_FALSE((ua::NodeId{std::uint16_t{2}, ua::Guid{}}.is_null()));
  EXPECT_FALSE((ua::NodeId{std::uint16_t{2}, ua::ByteString{}}.is_null()));
}

}  // namespace
