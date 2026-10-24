// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include <array>

#include "ua_localized_text.h"
#include "ua_address_space.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_node_utilities.h"
#include <boost/asio/thread_pool.hpp>

using namespace ua;

namespace
{

LocalizedText aggregate(std::initializer_list<std::pair<const char*, const char*>> entries)
{
  std::vector<LocalizedText::Scalar> translations;
  for (auto& [locale, text] : entries)
  {
    translations.emplace_back(LocaleId{String{locale}}, String{text});
  }
  return LocalizedText::from_translations(std::move(translations));
}

}  // namespace

TEST(LocalizedTextResolveTests, EmptyScalarResolvesToEmpty)
{
  LocalizedText lt;
  std::array<LocaleId, 1> preferred{LocaleId{String{"fr"}}};
  auto text = lt.resolve(preferred, LocaleId{String{"en"}});
  EXPECT_TRUE(text.locale().empty());
  EXPECT_TRUE(text.text().empty());
}

TEST(LocalizedTextResolveTests, EmptyPreferredUsesDefaultLocale)
{
  auto lt = aggregate({{"en", "Hello"}, {"fr", "Bonjour"}});
  std::array<LocaleId, 0> preferred{};
  auto text = lt.resolve(preferred, LocaleId{String{"fr"}});
  EXPECT_EQ(text, (LocalizedText{LocaleId{String{"fr"}}, String{"Bonjour"}}));
}

TEST(LocalizedTextResolveTests, ExactMatchPreferredWins)
{
  auto lt = aggregate({{"en", "Hello"}, {"fr", "Bonjour"}});
  std::array<LocaleId, 1> preferred{LocaleId{String{"fr"}}};
  auto text = lt.resolve(preferred, LocaleId{String{"en"}});
  EXPECT_EQ(text, (LocalizedText{LocaleId{String{"fr"}}, String{"Bonjour"}}));
}

TEST(LocalizedTextResolveTests, LanguageOnlyPartialMatchPreferredWins)
{
  auto lt = aggregate({{"en-IE", "Hello"}, {"fr-FR", "Bonjour"}, {"es-ES", "Ola"}});
  std::array<LocaleId, 1> preferred{LocaleId{String{"es"}}};
  auto text = lt.resolve(preferred, LocaleId{String{"en"}});
  EXPECT_EQ(text, (LocalizedText{LocaleId{String{"es-ES"}}, String{"Ola"}}));
}

TEST(LocalizedTextResolveTests, DefaultLocaleMissingFallsBackToFront)
{
  LocalizedText lt{LocaleId{String{"en"}}, String{"Hello"}};
  std::array<LocaleId, 0> preferred{};
  auto text = lt.resolve(preferred, LocaleId{String{"fr"}});
  EXPECT_EQ(text, (LocalizedText{LocaleId{String{"en"}}, String{"Hello"}}));
}

// ---------------------------------------------------------------------------
// DataTypeDefinition locale resolution via read_node_sync_attribute
// ---------------------------------------------------------------------------

namespace
{

/// Helper: create an EnumDefinition with a single field whose display_name
/// and description carry aggregate (multi-locale) LocalizedText values.
std::shared_ptr<EnumDefinition> make_enum_definition_with_translations()
{
  auto enumDef = std::make_shared<EnumDefinition>();
  Array<EnumField> fields;
  EnumField field;
  field.name() = String{"MyField"};
  field.value() = 0;
  field.display_name() = LocalizedText::from_translations({
    {LocaleId{String{"en-US"}}, String{"English"}},
    {LocaleId{String{"de-DE"}}, String{"Deutsch"}},
  });
  field.description() = LocalizedText::from_translations({
    {LocaleId{String{"en-US"}}, String{"English desc"}},
    {LocaleId{String{"de-DE"}}, String{"Deutsche Beschr."}},
  });
  fields.push_back(std::move(field));
  enumDef->fields() = std::move(fields);
  return enumDef;
}

}  // namespace

// A5a: When session locales do not match any translation, the server default
// locale is used to resolve nested LocalizedText fields inside a
// DataTypeDefinition (EnumField display_name / description).
TEST(LocalizedTextResolutionDataTypeDefinition, UsesDefaultLocaleWhenSessionLocaleHasNoMatch)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:TestUri", tp.get_executor());

  NodeId nodeId{1, 500};
  auto createResult = addressSpace.try_create_node_sync(nodeId, NodeClass::DataType, {});
  ASSERT_TRUE(createResult.is_good());
  auto node = createResult.value();

  auto dataType = node.as<DataTypeAccessor>();
  ASSERT_TRUE(dataType.has_value());
  dataType->set_data_type_definition(make_enum_definition_with_translations());

  // Session requests "fr" (no match); server default is "de-DE".
  std::vector<LocaleId> sessionLocales{LocaleId{String{"fr"}}};
  LocaleId defaultLocale{String{"de-DE"}};

  auto result = node_utils::read_node_sync_attribute(
    node, AttributeId::DataTypeDefinition, TimestampsToReturn::Neither, sessionLocales, defaultLocale);

  ASSERT_TRUE(result.value().is_structure());
  const auto* resolved = result.value().try_as<EnumDefinition>();
  ASSERT_NE(resolved, nullptr);
  ASSERT_FALSE(resolved->fields().empty());

  const auto& resolvedField = resolved->fields()[0];
  // display_name should have resolved to de-DE (the default locale).
  EXPECT_EQ(resolvedField.display_name().text(), String{"Deutsch"});
  EXPECT_EQ(resolvedField.display_name().locale(), LocaleId{String{"de-DE"}});
  // description should likewise resolve to de-DE.
  EXPECT_EQ(resolvedField.description().text(), String{"Deutsche Beschr."});
  EXPECT_EQ(resolvedField.description().locale(), LocaleId{String{"de-DE"}});
  ::ua::test_utils::drain_with_timeout(tp);
}

// A5b: When session locales contain a matching locale, it takes priority
// over the server default for nested LocalizedText fields.
TEST(LocalizedTextResolutionDataTypeDefinition, UsesSessionLocaleWhenItMatches)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:TestUri", tp.get_executor());

  NodeId nodeId{1, 501};
  auto createResult = addressSpace.try_create_node_sync(nodeId, NodeClass::DataType, {});
  ASSERT_TRUE(createResult.is_good());
  auto node = createResult.value();

  auto dataType = node.as<DataTypeAccessor>();
  ASSERT_TRUE(dataType.has_value());
  dataType->set_data_type_definition(make_enum_definition_with_translations());

  // Session requests "en-US" which matches; default is "de-DE".
  std::vector<LocaleId> sessionLocales{LocaleId{String{"en-US"}}};
  LocaleId defaultLocale{String{"de-DE"}};

  auto result = node_utils::read_node_sync_attribute(
    node, AttributeId::DataTypeDefinition, TimestampsToReturn::Neither, sessionLocales, defaultLocale);

  ASSERT_TRUE(result.value().is_structure());
  const auto* resolved = result.value().try_as<EnumDefinition>();
  ASSERT_NE(resolved, nullptr);
  ASSERT_FALSE(resolved->fields().empty());

  const auto& resolvedField = resolved->fields()[0];
  // display_name should have resolved to en-US (the session locale).
  EXPECT_EQ(resolvedField.display_name().text(), String{"English"});
  EXPECT_EQ(resolvedField.display_name().locale(), LocaleId{String{"en-US"}});
  // description should likewise resolve to en-US.
  EXPECT_EQ(resolvedField.description().text(), String{"English desc"});
  EXPECT_EQ(resolvedField.description().locale(), LocaleId{String{"en-US"}});
  ::ua::test_utils::drain_with_timeout(tp);
}

// WriteMask is a mandatory UInt32 attribute on every node (OPC 10000-3 5.2.7). A node with no
// explicit write mask must read back 0 (Good), not BadAttributeIdInvalid - which the UACTT Address
// Space WriteMask CUs (WriteMask 004 / Err-001 / Err-002; UserWriteMask remaps to WriteMask) flag.
TEST(WriteMaskAttributeRead, UnsetWriteMaskReadsAsZeroGood)
{
  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("uri:TestUri", tp.get_executor());

  NodeId nodeId{1, 700};
  auto createResult = addressSpace.try_create_node_sync(nodeId, NodeClass::Variable, {});
  ASSERT_TRUE(createResult.is_good());
  auto node = createResult.value();

  auto result = node_utils::read_node_sync_attribute(
    node, AttributeId::WriteMask, TimestampsToReturn::Neither, {}, LocaleId{});

  // An unset status is implicitly Good; the bug set it to BadAttributeIdInvalid.
  const bool statusGood = !result.status().has_value() || result.status()->is_good();
  EXPECT_TRUE(statusGood) << "reading an unset WriteMask must be Good, not an error";
  EXPECT_EQ(result.value().as<uint32_t>(), 0u);
  ::ua::test_utils::drain_with_timeout(tp);
}
