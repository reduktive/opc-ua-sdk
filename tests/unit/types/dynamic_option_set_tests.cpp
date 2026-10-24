// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_dynamic_option_set.h"

using namespace ua;

namespace
{

/// Helper: build an EnumDefinition with the given name/value pairs (bit numbers for option sets)
EnumDefinition make_enum_def(std::vector<std::pair<std::string, int64_t>> entries)
{
  EnumDefinition def;
  Array<EnumField> fields;
  fields.resize(entries.size());
  for (size_t i = 0; i < entries.size(); ++i)
  {
    fields[i].name() = String{entries[i].first};
    fields[i].value() = entries[i].second;
  }
  def.fields() = std::move(fields);
  return def;
}

shared_ptr<const DynamicEnumTypeDescriptor> make_permissions_descriptor()
{
  auto def = make_enum_def({{"Read", 0}, {"Write", 1}, {"Execute", 2}, {"Delete", 3}, {"Admin", 4}});
  return make_shared<const DynamicEnumTypeDescriptor>(
    String{"Permissions"}, ExpandedNodeId{NodeId{2, 3000}, "http://test.org/"}, true, std::move(def));
}

shared_ptr<const DynamicEnumTypeDescriptor> make_large_descriptor()
{
  // Create bits spread across multiple bytes
  auto def = make_enum_def({{"Bit0", 0}, {"Bit7", 7}, {"Bit8", 8}, {"Bit15", 15}, {"Bit16", 16}});
  return make_shared<const DynamicEnumTypeDescriptor>(
    String{"LargeFlags"}, ExpandedNodeId{NodeId{2, 4000}, "http://test.org/"}, true, std::move(def));
}

}  // namespace

// --- Construction and identity ---

TEST(DynamicOptionSet, DefaultConstruction)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);

  EXPECT_EQ(string_view(optSet.type_name()), "Permissions");
  EXPECT_TRUE(optSet.value().empty());
  EXPECT_TRUE(optSet.valid_bits().empty());
}

TEST(DynamicOptionSet, TypeId)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);

  auto typeId = optSet.type_id();
  EXPECT_EQ(typeId.node_id().identifier().get_numeric(), 3000u);
}

// --- Named bit access on Value ---

TEST(DynamicOptionSet, SetAndTestBit)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);

  EXPECT_FALSE(optSet.is_set("Read"));

  optSet.set_bit("Read");
  EXPECT_TRUE(optSet.is_set("Read"));
  EXPECT_FALSE(optSet.is_set("Write"));
}

TEST(DynamicOptionSet, SetMultipleBits)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);

  optSet.set_bit("Read");
  optSet.set_bit("Execute");
  optSet.set_bit("Admin");

  EXPECT_TRUE(optSet.is_set("Read"));
  EXPECT_FALSE(optSet.is_set("Write"));
  EXPECT_TRUE(optSet.is_set("Execute"));
  EXPECT_FALSE(optSet.is_set("Delete"));
  EXPECT_TRUE(optSet.is_set("Admin"));
}

TEST(DynamicOptionSet, ClearBit)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);

  optSet.set_bit("Write");
  EXPECT_TRUE(optSet.is_set("Write"));

  optSet.set_bit("Write", false);
  EXPECT_FALSE(optSet.is_set("Write"));
}

TEST(DynamicOptionSet, LargeBitNumbers)
{
  auto desc = make_large_descriptor();
  DynamicOptionSet optSet(desc);

  optSet.set_bit("Bit0");
  optSet.set_bit("Bit8");
  optSet.set_bit("Bit16");

  EXPECT_TRUE(optSet.is_set("Bit0"));
  EXPECT_FALSE(optSet.is_set("Bit7"));
  EXPECT_TRUE(optSet.is_set("Bit8"));
  EXPECT_FALSE(optSet.is_set("Bit15"));
  EXPECT_TRUE(optSet.is_set("Bit16"));

  // Value ByteString should be at least 3 bytes
  EXPECT_GE(optSet.value().size(), 3u);
}

// --- Valid bits ---

TEST(DynamicOptionSet, ValidBitsSetAndTest)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);

  EXPECT_FALSE(optSet.is_valid("Read"));

  optSet.set_valid("Read");
  EXPECT_TRUE(optSet.is_valid("Read"));
  EXPECT_FALSE(optSet.is_valid("Write"));
}

TEST(DynamicOptionSet, ValidBitsClear)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);

  optSet.set_valid("Admin");
  EXPECT_TRUE(optSet.is_valid("Admin"));

  optSet.set_valid("Admin", false);
  EXPECT_FALSE(optSet.is_valid("Admin"));
}

// --- Unknown bit name ---

TEST(DynamicOptionSet, UnknownBitNameThrows)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);

  EXPECT_THROW(optSet.is_set("Nonexistent"), UaException);
  EXPECT_THROW(optSet.set_bit("Nonexistent"), UaException);
  EXPECT_THROW(optSet.is_valid("Nonexistent"), UaException);
  EXPECT_THROW(optSet.set_valid("Nonexistent"), UaException);
}

// --- Clone ---

TEST(DynamicOptionSet, Clone)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);
  optSet.set_bit("Read");
  optSet.set_bit("Admin");
  optSet.set_valid("Read");

  auto cloned = optSet.clone();
  ASSERT_NE(cloned, nullptr);

  auto* clonedOptionSet = dynamic_cast<DynamicOptionSet*>(cloned.get());
  ASSERT_NE(clonedOptionSet, nullptr);

  EXPECT_TRUE(clonedOptionSet->is_set("Read"));
  EXPECT_TRUE(clonedOptionSet->is_set("Admin"));
  EXPECT_FALSE(clonedOptionSet->is_set("Write"));
  EXPECT_TRUE(clonedOptionSet->is_valid("Read"));
  EXPECT_FALSE(clonedOptionSet->is_valid("Admin"));
}

// --- Equality ---

TEST(DynamicOptionSet, EqualityMatching)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet a(desc);
  DynamicOptionSet b(desc);

  a.set_bit("Read");
  a.set_bit("Write");
  b.set_bit("Read");
  b.set_bit("Write");

  EXPECT_TRUE(a == b);
}

TEST(DynamicOptionSet, EqualityDifferentBits)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet a(desc);
  DynamicOptionSet b(desc);

  a.set_bit("Read");
  b.set_bit("Write");

  EXPECT_FALSE(a == b);
}

// --- to_string ---

TEST(DynamicOptionSet, ToStringEmpty)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);
  EXPECT_EQ(optSet.to_string(), "Permissions{}");
}

TEST(DynamicOptionSet, ToStringWithBits)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);
  optSet.set_bit("Read");
  optSet.set_bit("Execute");
  EXPECT_EQ(optSet.to_string(), "Permissions{Read, Execute}");
}

// --- Descriptor ---

TEST(DynamicOptionSet, Descriptor)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSet optSet(desc);
  EXPECT_EQ(&optSet.descriptor(), desc.get());
}
