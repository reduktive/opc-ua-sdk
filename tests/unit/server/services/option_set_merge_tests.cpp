// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_option_set_merge.h"
#include "ua_dynamic_option_set.h"
#include "ua_dynamic_enum_type_descriptor.h"

using namespace ua;
using namespace ua::server;

namespace
{

EnumDefinition make_enum_definition(std::vector<int64_t> bitNumbers)
{
  EnumDefinition def;
  for (auto bit : bitNumbers)
  {
    EnumField field;
    field.name() = String{fmt::format("Bit{}", bit)};
    field.value() = bit;
    def.fields().payload().push_back(std::move(field));
  }
  return def;
}

shared_ptr<DynamicEnumTypeDescriptor> make_descriptor(std::vector<int64_t> bitNumbers)
{
  return std::make_shared<DynamicEnumTypeDescriptor>(
    String{"TestOptionSet"}, ExpandedNodeId{NodeId{1, 100u}}, true, make_enum_definition(bitNumbers));
}

DynamicOptionSet make_option_set(
  shared_ptr<DynamicEnumTypeDescriptor> desc, ByteString value, ByteString validBits = {})
{
  DynamicOptionSet os{desc};
  os.value() = std::move(value);
  os.valid_bits() = std::move(validBits);
  return os;
}

// --- merge_option_set_value --------------------------------------------------

// @relation(SVR-DA-OPTSET-001, scope=function)
TEST(OptionSetMerge, PreservesUnchangedBits)
{
  auto desc = make_descriptor({0, 1, 2, 3, 4, 5, 6, 7});
  auto written = make_option_set(desc, {0x05}, {0x0F});
  auto current = make_option_set(desc, {0xA0});

  auto result = merge_option_set_value(written, current);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), ByteString({0xA5}));
}

// @relation(SVR-DA-OPTSET-001, scope=function)
TEST(OptionSetMerge, AllValidBits_FullReplace)
{
  auto desc = make_descriptor({0, 1, 2, 3, 4, 5, 6, 7});
  auto written = make_option_set(desc, {0x42}, {0xFF});
  auto current = make_option_set(desc, {0xA0});

  auto result = merge_option_set_value(written, current);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), ByteString({0x42}));
}

// @relation(SVR-DA-OPTSET-001, SVR-DA-OPTSET-003, scope=function)
TEST(OptionSetMerge, NoValidBits_NoChange)
{
  auto desc = make_descriptor({0, 1, 2, 3, 4, 5, 6, 7});
  auto written = make_option_set(desc, {0xFF}, {0x00});
  auto current = make_option_set(desc, {0xA0});

  auto result = merge_option_set_value(written, current);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), ByteString({0xA0}));
}

// @relation(SVR-DA-OPTSET-003, scope=function)
TEST(OptionSetMerge, SizeMismatch_BadOutOfRange)
{
  auto desc = make_descriptor({0, 1, 2, 3});
  auto written = make_option_set(desc, {0xFF}, {0x00, 0x00});
  auto current = make_option_set(desc, {0xA0});

  auto result = merge_option_set_value(written, current);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadOutOfRange);
}

// @relation(SVR-DA-OPTSET-001, scope=function)
TEST(OptionSetMerge, MultiByteValues)
{
  auto desc = make_descriptor({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
  // Merge only byte 0 bits, preserve byte 1
  auto written = make_option_set(desc, {0xAB, 0xCD}, {0xFF, 0x00});
  auto current = make_option_set(desc, {0x12, 0x34});

  auto result = merge_option_set_value(written, current);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value(), ByteString({0xAB, 0x34}));
}

// @relation(SVR-DA-OPTSET-001, scope=function)
TEST(OptionSetMerge, WrittenShorterThanCurrent)
{
  auto desc = make_descriptor({0, 1, 2, 3, 4, 5, 6, 7});
  auto written = make_option_set(desc, {0x05}, {0xFF});
  auto current = make_option_set(desc, {0xA0, 0xB0});

  auto result = merge_option_set_value(written, current);
  ASSERT_TRUE(result.is_good());
  // Byte 0: (0x05 & 0xFF) | (0xA0 & 0x00) = 0x05
  // Byte 1: (0x00 & 0x00) | (0xB0 & 0xFF) = 0xB0 (valid bits pad with 0, so current preserved)
  EXPECT_EQ(result.value(), ByteString({0x05, 0xB0}));
}

TEST(OptionSetMerge, CurrentShorterThanWritten)
{
  auto desc = make_descriptor({0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
  auto written = make_option_set(desc, {0x05, 0x06}, {0xFF, 0xFF});
  auto current = make_option_set(desc, {0xA0});

  auto result = merge_option_set_value(written, current);
  ASSERT_TRUE(result.is_good());
  // Byte 0: (0x05 & 0xFF) | (0xA0 & 0x00) = 0x05
  // Byte 1: (0x06 & 0xFF) | (0x00 & 0x00) = 0x06
  EXPECT_EQ(result.value(), ByteString({0x05, 0x06}));
}

// --- build_server_valid_bits_mask --------------------------------------------

namespace
{
Array<EnumField> make_fields(std::vector<int64_t> bitNumbers)
{
  Array<EnumField> fields;
  fields.reserve(bitNumbers.size());
  for (auto bit : bitNumbers)
  {
    EnumField f;
    f.value() = bit;
    fields.push_back(std::move(f));
  }
  return fields;
}
}  // namespace

// @relation(SVR-DA-OPTSET-001, scope=function)
TEST(OptionSetMerge, BuildMask_SingleBit)
{
  auto fields = make_fields({0});

  auto mask = build_server_valid_bits_mask(fields, 1);
  ASSERT_EQ(mask.size(), 1u);
  EXPECT_EQ(mask[0], 0x01);
}

TEST(OptionSetMerge, BuildMask_MultipleBits)
{
  auto fields = make_fields({0, 2, 7});

  auto mask = build_server_valid_bits_mask(fields, 1);
  ASSERT_EQ(mask.size(), 1u);
  EXPECT_EQ(mask[0], 0x85);  // bits 0, 2, 7
}

TEST(OptionSetMerge, BuildMask_MultiByte)
{
  auto fields = make_fields({9});  // byte 1, bit 1

  auto mask = build_server_valid_bits_mask(fields, 2);
  ASSERT_EQ(mask.size(), 2u);
  EXPECT_EQ(mask[0], 0x00);
  EXPECT_EQ(mask[1], 0x02);
}

TEST(OptionSetMerge, BuildMask_BitBeyondByteLength_Ignored)
{
  auto fields = make_fields({16});  // beyond 2-byte mask

  auto mask = build_server_valid_bits_mask(fields, 2);
  EXPECT_EQ(mask, ByteString({0x00, 0x00}));
}

// --- validate_client_valid_bits ----------------------------------------------

// @relation(SVR-DA-OPTSET-002, scope=function)
TEST(OptionSetMerge, Validate_AllBitsWithinMask_Good)
{
  ByteString clientBits{0x05};
  ByteString serverMask{0x0F};

  auto result = validate_client_valid_bits(clientBits, serverMask);
  EXPECT_TRUE(result.is_good());
}

// @relation(SVR-ATTR-WRITE-025, SVR-DA-OPTSET-002, scope=function)
TEST(OptionSetMerge, Validate_BitOutsideMask_BadOutOfRange)
{
  ByteString clientBits{0x10};
  ByteString serverMask{0x0F};

  auto result = validate_client_valid_bits(clientBits, serverMask);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadOutOfRange);
}

// @relation(SVR-DA-OPTSET-002, scope=function)
TEST(OptionSetMerge, Validate_EmptyServerMask_AllRejected)
{
  ByteString clientBits{0x01};
  ByteString serverMask{0x00};

  auto result = validate_client_valid_bits(clientBits, serverMask);
  EXPECT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), Status::BadOutOfRange);
}

TEST(OptionSetMerge, Validate_ClientZero_AlwaysGood)
{
  ByteString clientBits{0x00};
  ByteString serverMask{0x00};

  auto result = validate_client_valid_bits(clientBits, serverMask);
  EXPECT_TRUE(result.is_good());
}

// --- whole-write refusal and empty-validity no-op ----------------------------

// Part 8 section 7.17: a validity field naming a bit the OptionSet does not define makes the whole Write
// Bad_OutOfRange. A plausible implementation validates bit by bit and masks the client's validity
// down to the positions it recognises, then merges the remainder - which applies the defined bits
// of a Write the client has been told failed. The bits the type defines come from its
// EnumDefinition, so the mask is derived here rather than asserted by hand.
// @verifies AC-SVR-DA-OPTSET-002-VALIDITY-OUT-OF-RANGE
TEST(OptionSetMerge, ValidityNamingUndefinedBitRefusesTheWholeWrite)
{
  // The type defines bits 0, 1 and 2; bit 3 is not a bit this OptionSet owns.
  auto desc = make_descriptor({0, 1, 2});
  const auto& fields = desc->definition().fields();
  ASSERT_EQ(fields.size(), 3u);

  // One write marking bit 0 (defined) and bit 3 (undefined) valid, and setting both.
  auto written = make_option_set(desc, {0x09}, {0x09});
  auto current = make_option_set(desc, {0x00});

  auto serverMask = build_server_valid_bits_mask(fields, written.valid_bits().size());
  ASSERT_EQ(serverMask.size(), 1u);
  ASSERT_EQ(serverMask[0], 0x07);

  auto validated = validate_client_valid_bits(written.valid_bits(), serverMask);
  ASSERT_TRUE(validated.is_bad());
  EXPECT_EQ(validated.status_code(), Status::BadOutOfRange);

  // The refusal covers the defined bit carried by the same write: bit 0 on its own is accepted, so
  // the rejection above is of the entire validity field and not a per-bit filter letting bit 0 by.
  ByteString definedBitOnly{0x01};
  auto definedAlone = validate_client_valid_bits(definedBitOnly, serverMask);
  EXPECT_TRUE(definedAlone.is_good());

  // And the refusal withholds a real change: the merge that must not run would have written both
  // the defined and the undefined bit over the stored value.
  ASSERT_EQ(current.value(), ByteString({0x00}));
  auto wouldHaveMerged = merge_option_set_value(written, current);
  ASSERT_TRUE(wouldHaveMerged.is_good());
  EXPECT_EQ(wouldHaveMerged.value(), ByteString({0x09}));
}

// Part 5 section 12.18 / Part 8 "only those bits defined in validity are changed": an all-zero validity
// field is a no-op, and a validity field whose length disagrees with the written value's is
// malformed. A merge expressed as mask-and-assign zeroes the bits it was told to leave alone, and
// one that pads or truncates the shorter buffer turns a malformed request into a partial write.
// @verifies AC-SVR-DA-OPTSET-003-EMPTY-VALIDITY
TEST(OptionSetMerge, EmptyValidityLeavesStoredBitsAndLengthMismatchIsRefused)
{
  auto desc =
    make_descriptor({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23});
  auto current = make_option_set(desc, {0xA5, 0x5A, 0x3C});

  // First write: every bit of the written value differs from the stored one, and none is valid.
  auto zeroValidity = make_option_set(desc, {0xFF, 0xFF, 0xFF}, {0x00, 0x00, 0x00});

  auto unchanged = merge_option_set_value(zeroValidity, current);
  ASSERT_TRUE(unchanged.is_good());
  ASSERT_EQ(unchanged.value().size(), 3u);
  EXPECT_EQ(unchanged.value(), ByteString({0xA5, 0x5A, 0x3C}));

  // Second write: three-byte value against a two-byte validity field. Refused outright, so the
  // caller is left with no merged value to store - the leading two bytes are not applied.
  auto shortValidity = make_option_set(desc, {0xFF, 0xFF, 0xFF}, {0xFF, 0xFF});

  auto refusedShort = merge_option_set_value(shortValidity, current);
  ASSERT_TRUE(refusedShort.is_bad());
  EXPECT_EQ(refusedShort.status_code(), Status::BadOutOfRange);

  // Mismatch the other way: a validity field longer than the value it accompanies is refused too,
  // rather than truncated down to the value's length.
  auto longValidity = make_option_set(desc, {0xFF, 0xFF}, {0xFF, 0xFF, 0xFF});

  auto refusedLong = merge_option_set_value(longValidity, current);
  ASSERT_TRUE(refusedLong.is_bad());
  EXPECT_EQ(refusedLong.status_code(), Status::BadOutOfRange);

  // Neither refusal disturbed the stored value they were merged against.
  EXPECT_EQ(current.value(), ByteString({0xA5, 0x5A, 0x3C}));
}

}  // namespace
