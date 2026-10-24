// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_dynamic_views.h"

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

}  // namespace

TEST(DynamicOptionSetView, InitiallyEmpty)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSetView view(0, *desc);
  EXPECT_FALSE(view.is_set("Read"));
  EXPECT_FALSE(view.is_set("Write"));
  EXPECT_FALSE(view.is_set("Admin"));
  EXPECT_EQ(view.underlying(), 0u);
}

TEST(DynamicOptionSetView, SetAndTestBit)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSetView view(0, *desc);

  view.set_bit("Read");
  EXPECT_TRUE(view.is_set("Read"));
  EXPECT_FALSE(view.is_set("Write"));
  EXPECT_EQ(view.underlying(), 0b00001u);

  view.set_bit("Execute");
  EXPECT_TRUE(view.is_set("Read"));
  EXPECT_TRUE(view.is_set("Execute"));
  EXPECT_EQ(view.underlying(), 0b00101u);
}

TEST(DynamicOptionSetView, ClearBit)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSetView view(0b11111, *desc);  // All bits set

  EXPECT_TRUE(view.is_set("Delete"));
  view.set_bit("Delete", false);
  EXPECT_FALSE(view.is_set("Delete"));
  EXPECT_EQ(view.underlying(), 0b10111u);
}

// Covers SVR-IDENT-013 (coverage-audit retag).
TEST(DynamicOptionSetView, RoundTrip)
{
  auto desc = make_permissions_descriptor();
  uint64_t initial = 0b10101;  // Read, Execute, Admin
  DynamicOptionSetView view(initial, *desc);

  EXPECT_TRUE(view.is_set("Read"));
  EXPECT_FALSE(view.is_set("Write"));
  EXPECT_TRUE(view.is_set("Execute"));
  EXPECT_FALSE(view.is_set("Delete"));
  EXPECT_TRUE(view.is_set("Admin"));

  EXPECT_EQ(view.underlying(), initial);
}

TEST(DynamicOptionSetView, ToStringEmpty)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSetView view(0, *desc);
  EXPECT_EQ(view.to_string(), "Permissions{}");
}

TEST(DynamicOptionSetView, ToStringSingleBit)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSetView view(0b00010, *desc);  // Write only
  EXPECT_EQ(view.to_string(), "Permissions{Write}");
}

TEST(DynamicOptionSetView, ToStringMultipleBits)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSetView view(0b10101, *desc);  // Read, Execute, Admin
  EXPECT_EQ(view.to_string(), "Permissions{Read, Execute, Admin}");
}

TEST(DynamicOptionSetView, UnknownBitNameThrows)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSetView view(0, *desc);
  EXPECT_THROW(view.is_set("Nonexistent"), UaException);
  EXPECT_THROW(view.set_bit("Nonexistent"), UaException);
}

TEST(DynamicOptionSetView, Descriptor)
{
  auto desc = make_permissions_descriptor();
  DynamicOptionSetView view(0, *desc);
  EXPECT_EQ(&view.descriptor(), desc.get());
  EXPECT_TRUE(view.descriptor().is_option_set());
}
