// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "ua_argument.h"
#include "ua_array.h"
#include "ua_datatype_id.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_enum_value_type.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_range.h"
#include "ua_ref_structure.h"
#include "ua_variant.h"
#include "ua_string.h"
#include "ua_structure.h"

namespace ua
{
namespace
{

LocalizedText aggregate_en_de(const char* en, const char* de)
{
  std::vector<LocalizedText::Scalar> v;
  v.emplace_back(LocaleId{String{"en-US"}}, String{en});
  v.emplace_back(LocaleId{String{"de-DE"}}, String{de});
  return LocalizedText::from_translations(std::move(v));
}

std::array<LocaleId, 1> gLocalesEn{LocaleId{String{"en-US"}}};
std::array<LocaleId, 1> gLocalesDe{LocaleId{String{"de-DE"}}};

// ---------------------------------------------------------------------------
// Structure::resolve base - no-op default, virtual dispatch
// ---------------------------------------------------------------------------

TEST(StructureResolveTests, StructWithoutLocalizedTextEmitsNoOverride)
{
  // `NodeId` is not a Structure, pick a struct with no LT anywhere in its
  // transitive field set. `QualifiedName` is a built-in; use an
  // Argument sibling that has no LT. Concretely, we assert via the
  // virtual-dispatch negative: a struct type with *no* LT (e.g. any
  // `DataTypeDescription`-free simple type)  - but here we pick a
  // non-LT struct by using the base `NodeId` container, which is not a
  // Structure. Instead we test the positive path and assert the base
  // `Structure::resolve` does not mutate unrelated scalar fields in a
  // struct that DOES override resolve but whose non-LT fields stay
  // untouched.
  Argument arg;
  arg.name() = String{"inArg"};
  arg.data_type() = NodeId{DataTypeId::Double};
  arg.value_rank() = -1;
  arg.description() = aggregate_en_de("description", "Beschreibung");

  static_cast<Structure&>(arg).resolve(gLocalesEn);

  // Scalar description in en-US.
  EXPECT_TRUE(arg.description().is_scalar());
  EXPECT_EQ(arg.description().locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(arg.description().text(), String{"description"});

  // Non-LT fields untouched.
  EXPECT_EQ(arg.name(), String{"inArg"});
  EXPECT_EQ(arg.data_type(), (NodeId{DataTypeId::Double}));
  EXPECT_EQ(arg.value_rank(), -1);
}

TEST(StructureResolveTests, ArgumentResolveCollapsesDescriptionPerLocale)
{
  Argument arg;
  arg.description() = aggregate_en_de("hello", "hallo");

  Argument german = arg;
  german.resolve(gLocalesDe);
  EXPECT_TRUE(german.description().is_scalar());
  EXPECT_EQ(german.description().locale(), LocaleId{String{"de-DE"}});
  EXPECT_EQ(german.description().text(), String{"hallo"});

  // Negative: English branch yields different scalar on the same input.
  Argument english = arg;
  english.resolve(gLocalesEn);
  EXPECT_TRUE(english.description().is_scalar());
  EXPECT_EQ(english.description().text(), String{"hello"});
  EXPECT_NE(english.description().text(), german.description().text());
}

TEST(StructureResolveTests, EnumValueTypeResolvesBothLocalizedTextFields)
{
  EnumValueType ev;
  ev.value() = 42;
  ev.display_name() = aggregate_en_de("On", "An");
  ev.description() = aggregate_en_de("powered", "eingeschaltet");

  ev.resolve(gLocalesDe);

  EXPECT_TRUE(ev.display_name().is_scalar());
  EXPECT_TRUE(ev.description().is_scalar());
  EXPECT_EQ(ev.display_name().text(), String{"An"});
  EXPECT_EQ(ev.description().text(), String{"eingeschaltet"});
  EXPECT_EQ(ev.value(), 42);
}

TEST(StructureResolveTests, EnumFieldInheritsEnumValueTypeResolve)
{
  // EnumField adds `String name` on top of EnumValueType. It has no
  // direct LT fields - so resolve is inherited from EnumValueType.
  EnumField ef;
  ef.name() = String{"On"};
  ef.display_name() = aggregate_en_de("On", "An");
  ef.description() = aggregate_en_de("powered", "eingeschaltet");

  // Virtual dispatch: call via the base pointer to prove the EnumField
  // instance resolves through its EnumValueType override.
  static_cast<Structure&>(ef).resolve(gLocalesEn);

  EXPECT_TRUE(ef.display_name().is_scalar());
  EXPECT_EQ(ef.display_name().text(), String{"On"});
  EXPECT_EQ(ef.description().text(), String{"powered"});
  EXPECT_EQ(ef.name(), String{"On"});
}

TEST(StructureResolveTests, EnumDefinitionWalksArrayOfEnumFields)
{
  EnumDefinition def;
  Array<EnumField> fields;
  fields.resize(2);
  fields[0].name() = String{"On"};
  fields[0].display_name() = aggregate_en_de("On", "An");
  fields[0].description() = aggregate_en_de("powered", "eingeschaltet");
  fields[1].name() = String{"Off"};
  fields[1].display_name() = aggregate_en_de("Off", "Aus");
  fields[1].description() = aggregate_en_de("unpowered", "ausgeschaltet");
  def.fields() = std::move(fields);

  def.resolve(gLocalesDe);

  EXPECT_TRUE(def.fields()[0].display_name().is_scalar());
  EXPECT_EQ(def.fields()[0].display_name().text(), String{"An"});
  EXPECT_EQ(def.fields()[0].description().text(), String{"eingeschaltet"});
  EXPECT_EQ(def.fields()[1].display_name().text(), String{"Aus"});
  EXPECT_EQ(def.fields()[1].description().text(), String{"ausgeschaltet"});

  // Negative: the opposite locale on a fresh fixture produces
  // different text, proving the dispatch reaches every element.
  EnumDefinition english;
  Array<EnumField> engFields;
  engFields.resize(1);
  engFields[0].display_name() = aggregate_en_de("On", "An");
  english.fields() = std::move(engFields);
  english.resolve(gLocalesEn);
  EXPECT_EQ(english.fields()[0].display_name().text(), String{"On"});
}

// ---------------------------------------------------------------------------
// resolve_in_variant dispatch
// ---------------------------------------------------------------------------

TEST(ResolveInVariantTests, ScalarLocalizedTextInVariantIsNoOp)
{
  Variant v{LocalizedText{LocaleId{String{"en-US"}}, String{"hello"}}};
  resolve_in_variant(v, gLocalesDe);
  const auto& lt = v.as<LocalizedText>();
  EXPECT_TRUE(lt.is_scalar());
  EXPECT_EQ(lt.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(lt.text(), String{"hello"});
}

TEST(ResolveInVariantTests, AggregateLocalizedTextInVariantCollapses)
{
  Variant v{aggregate_en_de("hello", "hallo")};
  resolve_in_variant(v, gLocalesDe);
  const auto& lt = v.as<LocalizedText>();
  EXPECT_TRUE(lt.is_scalar());
  EXPECT_EQ(lt.locale(), LocaleId{String{"de-DE"}});
  EXPECT_EQ(lt.text(), String{"hallo"});
}

TEST(ResolveInVariantTests, ArrayOfLocalizedTextCollapsesPerElement)
{
  Array<LocalizedText> arr;
  arr.resize(2);
  arr[0] = aggregate_en_de("one", "eins");
  arr[1] = aggregate_en_de("two", "zwei");
  Variant v{std::move(arr)};

  resolve_in_variant(v, gLocalesDe);

  const auto& out = v.as<Array<LocalizedText>>();
  ASSERT_EQ(out.size(), 2u);
  EXPECT_TRUE(out[0].is_scalar());
  EXPECT_EQ(out[0].text(), String{"eins"});
  EXPECT_EQ(out[1].text(), String{"zwei"});
}

TEST(ResolveInVariantTests, StructureVariantInvokesVirtualResolve)
{
  Argument arg;
  arg.name() = String{"in"};
  arg.description() = aggregate_en_de("english", "deutsch");
  Variant v{std::move(arg)};

  resolve_in_variant(v, gLocalesEn);

  const auto* resolved = v.try_as<Argument>();
  ASSERT_NE(resolved, nullptr);
  EXPECT_TRUE(resolved->description().is_scalar());
  EXPECT_EQ(resolved->description().text(), String{"english"});
}

TEST(ResolveInVariantTests, PrimitiveVariantIsNoOp)
{
  Variant v{int32_t{42}};
  resolve_in_variant(v, gLocalesEn);
  EXPECT_TRUE(v.is_int32());
  EXPECT_EQ(v.as<int32_t>(), 42);
}

TEST(ResolveInVariantTests, StringVariantIsNoOpNotMistakenForLocalizedText)
{
  Variant v{String{"not localized"}};
  resolve_in_variant(v, gLocalesEn);
  EXPECT_TRUE(v.is_string());
  EXPECT_EQ(v.as<String>(), String{"not localized"});
}

// ---------------------------------------------------------------------------
// E1: Struct with genuinely no LocalizedText fields
// ---------------------------------------------------------------------------

TEST(StructureResolveTests, StructWithNoLocalizedTextFieldsIsNoOpOnResolve)
{
  // Range has only double low / double high - no LocalizedText anywhere
  // in its transitive field set. Calling resolve must be a harmless no-op.
  Range range;
  range.low() = 0.0;
  range.high() = 100.0;

  static_cast<Structure&>(range).resolve(gLocalesEn);

  EXPECT_EQ(range.low(), 0.0);
  EXPECT_EQ(range.high(), 100.0);
}

// ---------------------------------------------------------------------------
// E2: Variant holding a Structure without LocalizedText
// ---------------------------------------------------------------------------

TEST(ResolveInVariantTests, StructureWithoutLocalizedTextInVariantIsNoOp)
{
  Range range;
  range.low() = -10.0;
  range.high() = 50.0;
  Variant v{std::move(range)};

  resolve_in_variant(v, gLocalesDe);

  const auto* resolved = v.try_as<Range>();
  ASSERT_NE(resolved, nullptr);
  EXPECT_EQ(resolved->low(), -10.0);
  EXPECT_EQ(resolved->high(), 50.0);
}

// ---------------------------------------------------------------------------
// E3: Variant holding Array<RefStructure<Structure>> with LT fields
// ---------------------------------------------------------------------------

TEST(ResolveInVariantTests, ArrayOfStructureResolvesPerElementLocalizedText)
{
  Array<RefStructure<Structure>> arr;
  {
    auto arg0 = std::make_unique<Argument>();
    arg0->name() = String{"arg0"};
    arg0->description() = aggregate_en_de("first-en", "first-de");
    arr.push_back(RefStructure<Structure>{std::move(arg0)});

    auto arg1 = std::make_unique<Argument>();
    arg1->name() = String{"arg1"};
    arg1->description() = aggregate_en_de("second-en", "second-de");
    arr.push_back(RefStructure<Structure>{std::move(arg1)});
  }
  Variant v{std::move(arr)};

  resolve_in_variant(v, gLocalesDe);

  const auto& out = v.as<Array<RefStructure<Structure>>>();
  ASSERT_EQ(out.size(), 2u);

  const auto* r0 = dynamic_cast<const Argument*>(out[0].get());
  ASSERT_NE(r0, nullptr);
  EXPECT_TRUE(r0->description().is_scalar());
  EXPECT_EQ(r0->description().text(), String{"first-de"});
  EXPECT_EQ(r0->name(), String{"arg0"});

  const auto* r1 = dynamic_cast<const Argument*>(out[1].get());
  ASSERT_NE(r1, nullptr);
  EXPECT_TRUE(r1->description().is_scalar());
  EXPECT_EQ(r1->description().text(), String{"second-de"});
}

// ---------------------------------------------------------------------------
// E4: Empty Variant
// ---------------------------------------------------------------------------

TEST(ResolveInVariantTests, EmptyVariantIsNoOp)
{
  Variant v;
  ASSERT_TRUE(v.empty());

  resolve_in_variant(v, gLocalesEn);

  EXPECT_TRUE(v.empty());
}

}  // namespace
}  // namespace ua
