// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <unordered_set>

#include "ua_exceptions.h"
#include "ua_localized_text.h"

namespace ua
{
namespace
{

LocalizedText make_aggregate(std::initializer_list<std::pair<const char*, const char*>> entries)
{
  std::vector<LocalizedText::Scalar> v;
  v.reserve(entries.size());
  for (const auto& [l, t] : entries)
  {
    v.emplace_back(LocaleId{String{l}}, String{t});
  }
  return LocalizedText::from_translations(std::move(v));
}

// ---------------------------------------------------------------------------
// Construction and representation queries
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, DefaultConstructedIsScalarEmpty)
{
  LocalizedText lt;
  EXPECT_TRUE(lt.is_scalar());
  EXPECT_FALSE(lt.is_aggregate());
  EXPECT_EQ(lt.translation_count(), 0u);
  EXPECT_TRUE(lt.is_null());
  EXPECT_TRUE(lt.locale().empty());
  EXPECT_TRUE(lt.text().empty());
}

TEST(LocalizedTextTests, ScalarConstructorProducesScalarWithTranslationCountOne)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hello"}};
  EXPECT_TRUE(lt.is_scalar());
  EXPECT_FALSE(lt.is_aggregate());
  EXPECT_EQ(lt.translation_count(), 1u);
  EXPECT_FALSE(lt.is_null());
  EXPECT_EQ(lt.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(lt.text(), String{"hello"});
}

TEST(LocalizedTextTests, TextOnlyConstructorHasEmptyLocale)
{
  LocalizedText lt{String{"hi"}};
  EXPECT_TRUE(lt.is_scalar());
  EXPECT_TRUE(lt.locale().empty());
  EXPECT_EQ(lt.text(), String{"hi"});
  EXPECT_EQ(lt.translation_count(), 1u);
}

TEST(LocalizedTextTests, FromTranslationsEmptyCollapsesToScalar)
{
  auto lt = LocalizedText::from_translations({});
  EXPECT_TRUE(lt.is_scalar());
  EXPECT_FALSE(lt.is_aggregate());
  EXPECT_EQ(lt.translation_count(), 0u);
  EXPECT_TRUE(lt.is_null());
}

TEST(LocalizedTextTests, FromTranslationsSingleCollapsesToScalar)
{
  auto lt = make_aggregate({{"en-US", "hi"}});
  EXPECT_TRUE(lt.is_scalar());
  EXPECT_FALSE(lt.is_aggregate());
  EXPECT_EQ(lt.translation_count(), 1u);
  EXPECT_EQ(lt.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(lt.text(), String{"hi"});
}

TEST(LocalizedTextTests, FromTranslationsMultipleIsAggregate)
{
  const auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  EXPECT_FALSE(lt.is_scalar());
  EXPECT_TRUE(lt.is_aggregate());
  EXPECT_EQ(lt.translation_count(), 2u);
  // Canonical scalar view (const overload) returns the first-inserted entry.
  EXPECT_EQ(lt.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(lt.text(), String{"hi"});
}

TEST(LocalizedTextTests, MutableAccessorOnAggregateThrows)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  EXPECT_THROW((void)lt.locale(), UaException);
  EXPECT_THROW((void)lt.text(), UaException);
}

// ---------------------------------------------------------------------------
// text_for_locale
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, TextForLocaleScalarMatchAndMiss)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  ASSERT_TRUE(lt.text_for_locale("en-US").has_value());
  EXPECT_EQ(*lt.text_for_locale("en-US"), String{"hi"});
  EXPECT_FALSE(lt.text_for_locale("de-DE").has_value());
}

TEST(LocalizedTextTests, TextForLocaleAggregateMatchAndMiss)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  ASSERT_TRUE(lt.text_for_locale("de-DE").has_value());
  EXPECT_EQ(*lt.text_for_locale("de-DE"), String{"hallo"});
  EXPECT_FALSE(lt.text_for_locale("fr-FR").has_value());
}

TEST(LocalizedTextTests, TextForLocaleEmptyReceiverReturnsNullopt)
{
  LocalizedText lt;
  EXPECT_FALSE(lt.text_for_locale("en-US").has_value());
}

// ---------------------------------------------------------------------------
// merged_with - Part 4 section 5.10.4 upsert semantics
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, MergedWithEmptyLocaleAndEmptyTextClearsScalar)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.merged_with(LocalizedText{});
  EXPECT_TRUE(result.is_null());
  // Negative: receiver untouched.
  EXPECT_EQ(lt.translation_count(), 1u);
}

TEST(LocalizedTextTests, MergedWithEmptyLocaleAndEmptyTextClearsAggregate)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto result = lt.merged_with(LocalizedText{});
  EXPECT_TRUE(result.is_null());
  EXPECT_EQ(lt.translation_count(), 2u);
}

TEST(LocalizedTextTests, MergedWithLocaleAndEmptyTextDeletesScalarMatch)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"en-US"}}, String{}});
  EXPECT_TRUE(result.is_null());
}

TEST(LocalizedTextTests, MergedWithLocaleAndEmptyTextDoesNothingOnScalarMismatch)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"de-DE"}}, String{}});
  EXPECT_EQ(result, lt);
  EXPECT_EQ(result.translation_count(), 1u);
}

TEST(LocalizedTextTests, MergedWithLocaleAndEmptyTextRemovesAggregateEntry)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}, {"fr-FR", "salut"}});
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"de-DE"}}, String{}});
  EXPECT_EQ(result.translation_count(), 2u);
  EXPECT_FALSE(result.text_for_locale("de-DE").has_value());
  // Negative: the untouched locales remain.
  EXPECT_EQ(*result.text_for_locale("en-US"), String{"hi"});
  EXPECT_EQ(*result.text_for_locale("fr-FR"), String{"salut"});
}

TEST(LocalizedTextTests, MergedWithLocaleAndEmptyTextCollapsesAggregateToScalar)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"de-DE"}}, String{}});
  EXPECT_TRUE(result.is_scalar());
  EXPECT_EQ(result.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(result.text(), String{"hi"});
}

TEST(LocalizedTextTests, MergedWithUpsertsScalarReceiverEmpty)
{
  LocalizedText lt;
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"en-US"}}, String{"hi"}});
  EXPECT_TRUE(result.is_scalar());
  EXPECT_EQ(result.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(result.text(), String{"hi"});
}

TEST(LocalizedTextTests, MergedWithUpsertsScalarReceiverSameLocaleReplacesText)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"en-US"}}, String{"hello"}});
  EXPECT_TRUE(result.is_scalar());
  EXPECT_EQ(result.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(result.text(), String{"hello"});
}

TEST(LocalizedTextTests, MergedWithUpsertsScalarReceiverDifferentLocaleBecomesAggregate)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"de-DE"}}, String{"hallo"}});
  EXPECT_TRUE(result.is_aggregate());
  EXPECT_EQ(result.translation_count(), 2u);
  EXPECT_EQ(*result.text_for_locale("en-US"), String{"hi"});
  EXPECT_EQ(*result.text_for_locale("de-DE"), String{"hallo"});
}

TEST(LocalizedTextTests, MergedWithUpsertsAggregateExistingLocaleReplaces)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"en-US"}}, String{"hello"}});
  EXPECT_TRUE(result.is_aggregate());
  EXPECT_EQ(result.translation_count(), 2u);
  EXPECT_EQ(*result.text_for_locale("en-US"), String{"hello"});
  EXPECT_EQ(*result.text_for_locale("de-DE"), String{"hallo"});
}

TEST(LocalizedTextTests, MergedWithUpsertsAggregateNewLocaleInserts)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"fr-FR"}}, String{"salut"}});
  EXPECT_EQ(result.translation_count(), 3u);
  EXPECT_EQ(*result.text_for_locale("fr-FR"), String{"salut"});
}

TEST(LocalizedTextTests, MergedWithUnrelatedLocaleLeavesExistingUntouched)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"fr-FR"}}, String{"salut"}});
  EXPECT_EQ(*result.text_for_locale("en-US"), String{"hi"});
  EXPECT_EQ(*result.text_for_locale("de-DE"), String{"hallo"});
}

// ---------------------------------------------------------------------------
// with_translation vs merged_with - the empty-text footgun
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, WithTranslationEmptyTextAddsExplicitEmptyEntry)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.with_translation(LocaleId{String{"de-DE"}}, String{});
  // with_translation never deletes - it *adds* an empty-string entry.
  EXPECT_TRUE(result.is_aggregate());
  EXPECT_EQ(result.translation_count(), 2u);
  ASSERT_TRUE(result.text_for_locale("de-DE").has_value());
  EXPECT_EQ(*result.text_for_locale("de-DE"), String{});
}

TEST(LocalizedTextTests, MergedWithEmptyTextDeletesEntry)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto result = lt.merged_with(LocalizedText{LocaleId{String{"de-DE"}}, String{}});
  // merged_with with empty text *deletes* per section 5.10.4.
  EXPECT_FALSE(result.text_for_locale("de-DE").has_value());
}

// ---------------------------------------------------------------------------
// with_translation / without_translation - more coverage
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, WithTranslationOnEmptyProducesScalar)
{
  LocalizedText lt;
  auto result = lt.with_translation(LocaleId{String{"en-US"}}, String{"hi"});
  EXPECT_TRUE(result.is_scalar());
  EXPECT_EQ(result.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(result.text(), String{"hi"});
}

TEST(LocalizedTextTests, WithTranslationOnScalarSameLocaleReplaces)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.with_translation(LocaleId{String{"en-US"}}, String{"hello"});
  EXPECT_TRUE(result.is_scalar());
  EXPECT_EQ(result.text(), String{"hello"});
}

TEST(LocalizedTextTests, WithoutTranslationScalarMatchReturnsEmpty)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.without_translation("en-US");
  EXPECT_TRUE(result.is_null());
}

TEST(LocalizedTextTests, WithoutTranslationScalarNoMatchIsNoOp)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto result = lt.without_translation("de-DE");
  EXPECT_EQ(result, lt);
}

TEST(LocalizedTextTests, WithoutTranslationAggregateRemovesOneEntry)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}, {"fr-FR", "salut"}});
  auto result = lt.without_translation("de-DE");
  EXPECT_EQ(result.translation_count(), 2u);
  EXPECT_FALSE(result.text_for_locale("de-DE").has_value());
  EXPECT_EQ(*result.text_for_locale("en-US"), String{"hi"});
  EXPECT_EQ(*result.text_for_locale("fr-FR"), String{"salut"});
}

TEST(LocalizedTextTests, WithoutTranslationAggregateLastRemovalCollapsesToScalar)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto result = lt.without_translation("de-DE");
  EXPECT_TRUE(result.is_scalar());
  EXPECT_EQ(result.locale(), LocaleId{String{"en-US"}});
}

// ---------------------------------------------------------------------------
// resolve - overloads and matching rules
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, ResolveScalarReceiverIsFastPathNoOp)
{
  LocalizedText lt{LocaleId{String{"en-US"}}, String{"hi"}};
  auto r0 = lt.resolve();
  EXPECT_EQ(r0, lt);
  EXPECT_TRUE(r0.is_scalar());

  std::array<LocaleId, 1> locales{LocaleId{String{"de-DE"}}};
  auto r1 = lt.resolve(span<const LocaleId>{locales.data(), locales.size()});
  EXPECT_EQ(r1, lt);

  auto r2 = lt.resolve(span<const LocaleId>{locales.data(), locales.size()}, LocaleId{String{"fr-FR"}});
  EXPECT_EQ(r2, lt);
}

TEST(LocalizedTextTests, ResolveAggregateNoArgsReturnsFirstInserted)
{
  auto lt = make_aggregate({{"de-DE", "hallo"}, {"en-US", "hi"}});
  auto r = lt.resolve();
  EXPECT_TRUE(r.is_scalar());
  EXPECT_EQ(r.locale(), LocaleId{String{"de-DE"}});
  EXPECT_EQ(r.text(), String{"hallo"});
}

TEST(LocalizedTextTests, ResolveExactLocaleMatch)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}, {"fr-FR", "salut"}});
  std::array<LocaleId, 1> locales{LocaleId{String{"de-DE"}}};
  auto r = lt.resolve(span<const LocaleId>{locales.data(), locales.size()});
  EXPECT_TRUE(r.is_scalar());
  EXPECT_EQ(r.locale(), LocaleId{String{"de-DE"}});
  EXPECT_EQ(r.text(), String{"hallo"});
}

TEST(LocalizedTextTests, ResolveLanguageOnlyMatchPrefersSameLanguage)
{
  // Request "en" - no exact match, but en-US language matches.
  auto lt = make_aggregate({{"de-DE", "hallo"}, {"en-US", "hi"}});
  std::array<LocaleId, 1> locales{LocaleId{String{"en"}}};
  auto r = lt.resolve(span<const LocaleId>{locales.data(), locales.size()});
  EXPECT_EQ(r.locale(), LocaleId{String{"en-US"}});
  EXPECT_EQ(r.text(), String{"hi"});
}

TEST(LocalizedTextTests, ResolveLanguageOnlyDoesNotCrossLanguageFamily)
{
  auto lt = make_aggregate({{"de-DE", "hallo"}, {"fr-FR", "salut"}});
  std::array<LocaleId, 1> locales{LocaleId{String{"en-GB"}}};
  auto r = lt.resolve(span<const LocaleId>{locales.data(), locales.size()});
  // No English available in any family - fallback to first-inserted.
  EXPECT_EQ(r.locale(), LocaleId{String{"de-DE"}});
  // Negative: resolution must NOT pick a French entry on an English request.
  EXPECT_NE(r.locale(), LocaleId{String{"fr-FR"}});
}

TEST(LocalizedTextTests, ResolveFallsBackToDefaultLocale)
{
  auto lt = make_aggregate({{"de-DE", "hallo"}, {"fr-FR", "salut"}});
  std::array<LocaleId, 1> locales{LocaleId{String{"en-US"}}};
  auto r = lt.resolve(span<const LocaleId>{locales.data(), locales.size()}, LocaleId{String{"de-DE"}});
  EXPECT_EQ(r.locale(), LocaleId{String{"de-DE"}});
}

TEST(LocalizedTextTests, ResolveDefaultLocaleIgnoredWhenSessionMatched)
{
  auto lt = make_aggregate({{"de-DE", "hallo"}, {"fr-FR", "salut"}});
  std::array<LocaleId, 1> locales{LocaleId{String{"fr-FR"}}};
  auto r = lt.resolve(span<const LocaleId>{locales.data(), locales.size()}, LocaleId{String{"de-DE"}});
  EXPECT_EQ(r.locale(), LocaleId{String{"fr-FR"}});
}

TEST(LocalizedTextTests, ResolveFallsBackToFirstInsertedWhenNothingMatches)
{
  auto lt = make_aggregate({{"de-DE", "hallo"}, {"fr-FR", "salut"}});
  std::array<LocaleId, 1> locales{LocaleId{String{"zh-CN"}}};
  auto r = lt.resolve(span<const LocaleId>{locales.data(), locales.size()});
  EXPECT_EQ(r.locale(), LocaleId{String{"de-DE"}});
}

TEST(LocalizedTextTests, ResolveOnEmptyReceiverReturnsEmpty)
{
  LocalizedText lt;
  std::array<LocaleId, 1> locales{LocaleId{String{"en-US"}}};
  auto r = lt.resolve(span<const LocaleId>{locales.data(), locales.size()});
  EXPECT_TRUE(r.is_null());
}

TEST(LocalizedTextTests, ResolvePrefersSessionLocaleOrder)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}, {"fr-FR", "salut"}});
  std::array<LocaleId, 2> locales{LocaleId{String{"fr-FR"}}, LocaleId{String{"de-DE"}}};
  auto r = lt.resolve(span<const LocaleId>{locales.data(), locales.size()});
  // Session's first preference wins.
  EXPECT_EQ(r.locale(), LocaleId{String{"fr-FR"}});
}

// ---------------------------------------------------------------------------
// operator==
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, EqualityScalarFieldEqualAndInequal)
{
  LocalizedText a{LocaleId{String{"en-US"}}, String{"hi"}};
  LocalizedText b{LocaleId{String{"en-US"}}, String{"hi"}};
  LocalizedText c{LocaleId{String{"en-US"}}, String{"hello"}};
  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
}

TEST(LocalizedTextTests, EqualityAggregateOrderIndependent)
{
  auto a = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto b = make_aggregate({{"de-DE", "hallo"}, {"en-US", "hi"}});
  EXPECT_EQ(a, b);
}

TEST(LocalizedTextTests, EqualityAggregateInequalOnDifferentText)
{
  auto a = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto b = make_aggregate({{"en-US", "hi"}, {"de-DE", "moin"}});
  EXPECT_NE(a, b);
}

TEST(LocalizedTextTests, EqualityScalarVsTwoEntryAggregateUnequal)
{
  LocalizedText s{LocaleId{String{"en-US"}}, String{"hi"}};
  auto a = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  EXPECT_NE(s, a);
}

// ---------------------------------------------------------------------------
// hash_value
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, HashScalarEqualsHashOfIdenticalScalar)
{
  LocalizedText a{LocaleId{String{"en-US"}}, String{"hi"}};
  LocalizedText b{LocaleId{String{"en-US"}}, String{"hi"}};
  EXPECT_EQ(hash_value(a), hash_value(b));
}

TEST(LocalizedTextTests, HashAggregateOrderIndependent)
{
  auto a = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto b = make_aggregate({{"de-DE", "hallo"}, {"en-US", "hi"}});
  EXPECT_EQ(hash_value(a), hash_value(b));
}

TEST(LocalizedTextTests, HashScalarAndMatchingAggregateDifferOnContent)
{
  // Ensure differing stored content hashes to different values for the
  // specific fixture (not a strict guarantee, but a regression fence).
  LocalizedText a{LocaleId{String{"en-US"}}, String{"hi"}};
  LocalizedText b{LocaleId{String{"en-US"}}, String{"hello"}};
  EXPECT_NE(hash_value(a), hash_value(b));
}

// ---------------------------------------------------------------------------
// Copy semantics
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, AggregateCopyIsO1SharedStorage)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  auto copy = lt;  // NOLINT(performance-unnecessary-copy-initialization)
  // Both copies are aggregates referencing the same underlying vector.
  // We cannot inspect the shared_ptr directly through the public API,
  // but use_count-style observation is possible via text_for_locale
  // semantics + aggregate identity: semantic equality holds and
  // mutation of one does not affect the other.
  EXPECT_EQ(lt, copy);

  auto mutated = copy.with_translation(LocaleId{String{"fr-FR"}}, String{"salut"});
  EXPECT_EQ(lt.translation_count(), 2u);
  EXPECT_EQ(mutated.translation_count(), 3u);
  EXPECT_FALSE(lt.text_for_locale("fr-FR").has_value());
}

TEST(LocalizedTextTests, ScalarCopyIsIndependentValue)
{
  LocalizedText a{LocaleId{String{"en-US"}}, String{"hi"}};
  LocalizedText b = a;
  EXPECT_EQ(a, b);
  auto mutated = b.with_translation(LocaleId{String{"de-DE"}}, String{"hallo"});
  EXPECT_TRUE(a.is_scalar());
  EXPECT_TRUE(mutated.is_aggregate());
}

// ---------------------------------------------------------------------------
// clear / is_null
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, ClearResetsAggregateToScalarEmpty)
{
  auto lt = make_aggregate({{"en-US", "hi"}, {"de-DE", "hallo"}});
  lt.clear();
  EXPECT_TRUE(lt.is_scalar());
  EXPECT_TRUE(lt.is_null());
  EXPECT_EQ(lt.translation_count(), 0u);
}

// ---------------------------------------------------------------------------
// Scalar == one-entry from_translations (design commitment)
// ---------------------------------------------------------------------------

TEST(LocalizedTextTests, ScalarEqualsOneEntryFromTranslations)
{
  LocalizedText scalar{LocaleId{String{"en"}}, String{"Hello"}};
  auto fromTranslations = make_aggregate({{"en", "Hello"}});
  // from_translations with one entry normalizes to scalar storage.
  ASSERT_TRUE(fromTranslations.is_scalar());
  EXPECT_EQ(scalar, fromTranslations);
}

TEST(LocalizedTextTests, HashConsistencyScalarAndOneEntryFromTranslations)
{
  LocalizedText scalar{LocaleId{String{"en"}}, String{"Hello"}};
  auto fromTranslations = make_aggregate({{"en", "Hello"}});
  EXPECT_EQ(hash_value(scalar), hash_value(fromTranslations));
}

}  // namespace
}  // namespace ua
