// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_dynamic_views.h"

using namespace ua;

namespace
{

/// Helper: build an EnumDefinition with the given name/value pairs
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

shared_ptr<const DynamicEnumTypeDescriptor> make_color_descriptor()
{
  auto def = make_enum_def({{"Red", 0}, {"Green", 1}, {"Blue", 2}, {"Alpha", 3}});
  return make_shared<const DynamicEnumTypeDescriptor>(
    String{"Color"}, ExpandedNodeId{NodeId{2, 1000}, "http://test.org/"}, false, std::move(def));
}

}  // namespace

// --- DynamicEnumTypeDescriptor tests ---

TEST(DynamicEnumTypeDescriptor, TypeNameAndId)
{
  auto desc = make_color_descriptor();
  EXPECT_EQ(string_view(desc->type_name()), "Color");
  EXPECT_EQ(desc->type_id().node_id().identifier().get_numeric(), 1000u);
  EXPECT_FALSE(desc->is_option_set());
}

TEST(DynamicEnumTypeDescriptor, NameForValueKnown)
{
  auto desc = make_color_descriptor();
  auto name = desc->name_for_value(0);
  ASSERT_TRUE(name.has_value());
  EXPECT_EQ(*name, "Red");

  name = desc->name_for_value(2);
  ASSERT_TRUE(name.has_value());
  EXPECT_EQ(*name, "Blue");
}

TEST(DynamicEnumTypeDescriptor, NameForValueUnknown)
{
  auto desc = make_color_descriptor();
  auto name = desc->name_for_value(99);
  EXPECT_FALSE(name.has_value());
}

TEST(DynamicEnumTypeDescriptor, ValueForNameKnown)
{
  auto desc = make_color_descriptor();
  auto val = desc->value_for_name("Green");
  ASSERT_TRUE(val.has_value());
  EXPECT_EQ(*val, 1);
}

TEST(DynamicEnumTypeDescriptor, ValueForNameUnknown)
{
  auto desc = make_color_descriptor();
  auto val = desc->value_for_name("Yellow");
  EXPECT_FALSE(val.has_value());
}

TEST(DynamicEnumTypeDescriptor, Definition)
{
  auto desc = make_color_descriptor();
  EXPECT_EQ(desc->definition().fields().size(), 4u);
}

// --- DynamicEnumView tests ---

TEST(DynamicEnumView, ValueNameKnown)
{
  auto desc = make_color_descriptor();
  DynamicEnumView view(1, *desc);
  EXPECT_EQ(view.value(), 1);
  EXPECT_EQ(view.value_name(), "Green");
}

TEST(DynamicEnumView, ValueNameUnknown)
{
  auto desc = make_color_descriptor();
  DynamicEnumView view(42, *desc);
  EXPECT_EQ(view.value(), 42);
  EXPECT_EQ(view.value_name(), string_view{});
  EXPECT_TRUE(view.value_name().empty());
}

TEST(DynamicEnumView, ToStringKnown)
{
  auto desc = make_color_descriptor();
  DynamicEnumView view(2, *desc);
  EXPECT_EQ(view.to_string(), "Color::Blue");
}

TEST(DynamicEnumView, ToStringUnknown)
{
  auto desc = make_color_descriptor();
  DynamicEnumView view(42, *desc);
  EXPECT_EQ(view.to_string(), "Color(42)");
}

TEST(DynamicEnumView, ToStringNegativeValue)
{
  auto def = make_enum_def({{"Error", -1}, {"None", 0}});
  auto desc = make_shared<const DynamicEnumTypeDescriptor>(
    String{"Status"}, ExpandedNodeId{NodeId{2, 2000}, "http://test.org/"}, false, std::move(def));

  DynamicEnumView knownView(-1, *desc);
  EXPECT_EQ(knownView.to_string(), "Status::Error");

  DynamicEnumView unknownView(-99, *desc);
  EXPECT_EQ(unknownView.to_string(), "Status(-99)");
}

TEST(DynamicEnumView, Descriptor)
{
  auto desc = make_color_descriptor();
  DynamicEnumView view(0, *desc);
  EXPECT_EQ(&view.descriptor(), desc.get());
}
