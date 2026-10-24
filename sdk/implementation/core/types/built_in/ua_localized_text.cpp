// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <algorithm>

#include <boost/container_hash/hash.hpp>

#include "ua_error_detail.h"
#include "ua_localized_text.h"
#include "ua_utilities.h"

namespace ua
{

namespace
{

// Normalise a vector of translations into either a Scalar (0 or 1
// entries) or a SharedAggregate (2+ entries). A SharedAggregate with
// fewer than two entries is never stored - the invariant documented on
// LocalizedText::mRepresentation.
std::variant<LocalizedText::Scalar, shared_ptr<const std::vector<LocalizedText::Scalar>>> normalise(
  std::vector<LocalizedText::Scalar> translations)
{
  using Scalar = LocalizedText::Scalar;
  using Aggregate = std::vector<Scalar>;
  using SharedAggregate = shared_ptr<const Aggregate>;

  if (translations.empty())
  {
    return Scalar{};
  }
  if (translations.size() == 1)
  {
    return std::move(translations.front());
  }
  auto owned = std::make_shared<Aggregate>(std::move(translations));
  return SharedAggregate{std::const_pointer_cast<const Aggregate>(owned)};
}

bool scalar_is_empty(const LocalizedText::Scalar& s) noexcept
{
  return s.first.empty() && s.second.empty();
}

// Language-only prefix of a locale id. A locale like "en-US" has
// language "en"; a bare "en" returns itself.
String language_prefix(const LocaleId& locale)
{
  auto [language, region] = LocalizedText::parse_locale_id(locale);
  (void)region;
  return language;
}

// Find an exact-locale translation in [begin, end); returns end() if
// none match.
template<typename It>
It find_exact(It begin, It end, const LocaleId& locale)
{
  return std::find_if(begin, end, [&](const LocalizedText::Scalar& entry) { return entry.first == locale; });
}

// Find a translation whose language matches `locale`'s language prefix.
template<typename It>
It find_language(It begin, It end, const LocaleId& locale)
{
  auto requestedLanguage = language_prefix(locale);
  if (requestedLanguage.empty())
  {
    return end;
  }
  return std::find_if(begin,
    end,
    [&](const LocalizedText::Scalar& entry) { return language_prefix(entry.first) == requestedLanguage; });
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction and representation queries
// ---------------------------------------------------------------------------

LocalizedText::LocalizedText(LocaleId locale, String text)
  : mRepresentation(Scalar{std::move(locale), std::move(text)})
{}

LocalizedText::LocalizedText(String text) : mRepresentation(Scalar{LocaleId{}, std::move(text)})
{}

LocalizedText LocalizedText::from_translations(std::vector<Scalar> translations)
{
  LocalizedText result;
  result.mRepresentation = normalise(std::move(translations));
  return result;
}

bool LocalizedText::is_scalar() const noexcept
{
  return std::holds_alternative<Scalar>(mRepresentation);
}

bool LocalizedText::is_aggregate() const noexcept
{
  return std::holds_alternative<SharedAggregate>(mRepresentation);
}

std::size_t LocalizedText::translation_count() const noexcept
{
  if (auto* s = scalar_ptr())
  {
    return scalar_is_empty(*s) ? 0 : 1;
  }
  // noexcept query, so it cannot use the throwing aggregate_ref(): guard the
  // deref explicitly. The null branch is unreachable under the representation
  // invariant (not scalar => non-null aggregate); 0 is the degenerate count.
  if (const auto* entries = aggregate_ptr())
  {
    return entries->size();
  }
  return 0;
}

const LocalizedText::Scalar* LocalizedText::scalar_ptr() const noexcept
{
  return std::get_if<Scalar>(&mRepresentation);
}

const LocalizedText::AggregateStorage* LocalizedText::aggregate_ptr() const noexcept
{
  if (auto* handle = std::get_if<SharedAggregate>(&mRepresentation))
  {
    return handle->get();
  }
  return nullptr;
}

const LocalizedText::AggregateStorage& LocalizedText::aggregate_ref() const
{
  const auto* entries = aggregate_ptr();
  if (!entries)
  {
    // Unreachable under the representation invariant (callers reach here
    // only after scalar_ptr() returned null, which means the variant holds
    // a SharedAggregate, and normalise() never stores a null handle). Fail
    // loudly rather than dereference null.
    throw UaException(Status::BadInternalError,
      make_error_detail("LocalizedTextAggregateInvariant",
        "LocalizedText aggregate handle was null where the representation "
        "invariant guarantees a non-null aggregate",
        "LocalizedText"));
  }
  return *entries;
}

// ---------------------------------------------------------------------------
// Canonical scalar view
// ---------------------------------------------------------------------------

const LocaleId& LocalizedText::locale() const
{
  if (auto* s = scalar_ptr())
  {
    return s->first;
  }
  return aggregate_ref().front().first;
}

const String& LocalizedText::text() const
{
  if (auto* s = scalar_ptr())
  {
    return s->second;
  }
  return aggregate_ref().front().second;
}

LocaleId& LocalizedText::locale()
{
  auto* s = std::get_if<Scalar>(&mRepresentation);
  if (!s)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("LocalizedTextMutationOnAggregate",
        "LocalizedText::locale() (mutable) called on an aggregate value; "
        "use with_translation / merged_with to mutate aggregates",
        "LocalizedText")
        .context(ua::ContextKeys::length, std::to_string(translation_count())));
  }
  return s->first;
}

String& LocalizedText::text()
{
  auto* s = std::get_if<Scalar>(&mRepresentation);
  if (!s)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("LocalizedTextMutationOnAggregate",
        "LocalizedText::text() (mutable) called on an aggregate value; "
        "use with_translation / merged_with to mutate aggregates",
        "LocalizedText")
        .context(ua::ContextKeys::length, std::to_string(translation_count())));
  }
  return s->second;
}

std::vector<LocalizedText::Scalar> LocalizedText::translations() const
{
  if (auto* s = scalar_ptr())
  {
    if (scalar_is_empty(*s))
    {
      return {};
    }
    return {*s};
  }
  const auto& entries = aggregate_ref();
  return std::vector<Scalar>{entries.begin(), entries.end()};
}

std::optional<String> LocalizedText::text_for_locale(string_view locale) const
{
  if (auto* s = scalar_ptr())
  {
    if (scalar_is_empty(*s))
    {
      return std::nullopt;
    }
    if (string_view{s->first} == locale)
    {
      return s->second;
    }
    return std::nullopt;
  }
  const auto& entries = aggregate_ref();
  auto it = std::find_if(
    entries.begin(), entries.end(), [&](const Scalar& entry) { return string_view{entry.first} == locale; });
  if (it == entries.end())
  {
    return std::nullopt;
  }
  return it->second;
}

bool LocalizedText::is_null() const
{
  if (auto* s = scalar_ptr())
  {
    return scalar_is_empty(*s);
  }
  return false;  // aggregates always carry >= 2 entries
}

void LocalizedText::clear()
{
  mRepresentation = Scalar{};
}

// ---------------------------------------------------------------------------
// Immutable-by-value builder API
// ---------------------------------------------------------------------------

LocalizedText LocalizedText::with_translation(LocaleId locale, String text) const
{
  if (auto* s = scalar_ptr())
  {
    if (scalar_is_empty(*s))
    {
      return LocalizedText{std::move(locale), std::move(text)};
    }
    if (s->first == locale)
    {
      return LocalizedText{std::move(locale), std::move(text)};
    }
    std::vector<Scalar> newTranslations;
    newTranslations.reserve(2);
    newTranslations.push_back(*s);
    newTranslations.emplace_back(std::move(locale), std::move(text));
    return from_translations(std::move(newTranslations));
  }

  const auto& entries = aggregate_ref();
  std::vector<Scalar> next(entries.begin(), entries.end());
  auto it = find_exact(next.begin(), next.end(), locale);
  if (it != next.end())
  {
    it->second = std::move(text);
  }
  else
  {
    next.emplace_back(std::move(locale), std::move(text));
  }
  return from_translations(std::move(next));
}

LocalizedText LocalizedText::without_translation(string_view locale) const
{
  if (auto* s = scalar_ptr())
  {
    if (scalar_is_empty(*s))
    {
      return *this;
    }
    if (string_view{s->first} == locale)
    {
      return LocalizedText{};
    }
    return *this;
  }

  const auto& entries = aggregate_ref();
  std::vector<Scalar> next;
  next.reserve(entries.size());
  for (const auto& entry : entries)
  {
    if (string_view{entry.first} != locale)
    {
      next.push_back(entry);
    }
  }
  return from_translations(std::move(next));
}

// ---------------------------------------------------------------------------
// Spec 5.10.4 merge semantics
// ---------------------------------------------------------------------------

LocalizedText LocalizedText::merged_with(const LocalizedText& update) const
{
  // Spec expects the update to be a scalar, but handle aggregate
  // updates defensively by folding them entry-by-entry.
  if (const auto* updateScalar = update.scalar_ptr())
  {
    const auto& incomingLocale = updateScalar->first;
    const auto& incomingText = updateScalar->second;

    if (incomingLocale.empty() && incomingText.empty())
    {
      return LocalizedText{};  // clear all
    }
    if (incomingText.empty())
    {
      return without_translation(incomingLocale);
    }
    return with_translation(incomingLocale, incomingText);
  }

  LocalizedText result = *this;
  for (const auto& entry : update.aggregate_ref())
  {
    result = result.merged_with(LocalizedText{entry.first, entry.second});
  }
  return result;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

LocalizedText LocalizedText::resolve() const
{
  if (is_scalar())
  {
    return *this;
  }
  // Aggregate: return the first-inserted entry as a scalar.
  const auto& entries = aggregate_ref();
  return LocalizedText{entries.front().first, entries.front().second};
}

LocalizedText LocalizedText::resolve(span<const LocaleId> locales) const
{
  if (is_scalar())
  {
    return *this;
  }

  const auto& entries = aggregate_ref();

  // 1. Exact-locale match in preference order.
  for (const auto& requested : locales)
  {
    if (requested.empty())
    {
      continue;
    }
    auto it = find_exact(entries.begin(), entries.end(), requested);
    if (it != entries.end())
    {
      return LocalizedText{it->first, it->second};
    }
  }

  // 2. Language-only match.
  for (const auto& requested : locales)
  {
    if (requested.empty())
    {
      continue;
    }
    auto it = find_language(entries.begin(), entries.end(), requested);
    if (it != entries.end())
    {
      return LocalizedText{it->first, it->second};
    }
  }

  // 3. Fallback to first-inserted.
  return LocalizedText{entries.front().first, entries.front().second};
}

LocalizedText LocalizedText::resolve(span<const LocaleId> locales, const LocaleId& defaultLocale) const
{
  if (is_scalar())
  {
    return *this;
  }

  const auto& entries = aggregate_ref();

  // 1. Exact-locale match in session preference order.
  for (const auto& requested : locales)
  {
    if (requested.empty())
    {
      continue;
    }
    auto it = find_exact(entries.begin(), entries.end(), requested);
    if (it != entries.end())
    {
      return LocalizedText{it->first, it->second};
    }
  }

  // 2. Language-only match in session preference order.
  for (const auto& requested : locales)
  {
    if (requested.empty())
    {
      continue;
    }
    auto it = find_language(entries.begin(), entries.end(), requested);
    if (it != entries.end())
    {
      return LocalizedText{it->first, it->second};
    }
  }

  // 3. Server-wide default locale (exact then language).
  if (!defaultLocale.empty())
  {
    auto it = find_exact(entries.begin(), entries.end(), defaultLocale);
    if (it == entries.end())
    {
      it = find_language(entries.begin(), entries.end(), defaultLocale);
    }
    if (it != entries.end())
    {
      return LocalizedText{it->first, it->second};
    }
  }

  // 4. Fallback to first-inserted.
  return LocalizedText{entries.front().first, entries.front().second};
}

// ---------------------------------------------------------------------------
// Equality and hash
// ---------------------------------------------------------------------------

bool operator==(const LocalizedText& lhs, const LocalizedText& rhs)
{
  const auto* lScalar = lhs.scalar_ptr();
  const auto* rScalar = rhs.scalar_ptr();

  if (lScalar && rScalar)
  {
    return *lScalar == *rScalar;
  }

  if (lScalar)
  {
    // lhs is scalar, rhs is aggregate (size >= 2 by invariant).
    // A scalar equals a one-entry aggregate only; storage never holds
    // a one-entry aggregate, but tests may construct one via direct
    // variant access. Handle it defensively: equal iff aggregate has
    // exactly one entry matching the scalar.
    const auto& entries = rhs.aggregate_ref();
    return entries.size() == 1 && entries.front() == *lScalar;
  }
  if (rScalar)
  {
    const auto& entries = lhs.aggregate_ref();
    return entries.size() == 1 && entries.front() == *rScalar;
  }

  // Both aggregate: set equality, order-independent.
  const auto& le = lhs.aggregate_ref();
  const auto& re = rhs.aggregate_ref();
  if (&le == &re)
  {
    return true;  // same underlying aggregate (shared storage)
  }
  if (le.size() != re.size())
  {
    return false;
  }
  for (const auto& entry : le)
  {
    auto it = std::find(re.begin(), re.end(), entry);
    if (it == re.end())
    {
      return false;
    }
  }
  return true;
}

size_t hash_value(const ua::LocalizedText& lt) noexcept
{
  if (const auto* s = lt.scalar_ptr())
  {
    size_t seed{0};
    boost::hash_combine(seed, s->first);
    boost::hash_combine(seed, s->second);
    return seed;
  }
  // Aggregate hash: XOR per-entry scalar-shaped hashes. Order-independent so set equality
  // and hash agree. Use the non-throwing aggregate_ptr() (NOT aggregate_ref(), which throws
  // BadInternalError on a null handle): std::hash<LocalizedText> is noexcept, so a throw here
  // would std::terminate when hashing a null/moved-from key. A null handle (precluded by the
  // representation invariant) hashes to the 0 sentinel.
  const auto* entries = lt.aggregate_ptr();
  if (!entries)
  {
    return 0;
  }
  size_t acc{0};
  for (const auto& entry : *entries)
  {
    size_t entrySeed{0};
    boost::hash_combine(entrySeed, entry.first);
    boost::hash_combine(entrySeed, entry.second);
    acc ^= entrySeed;
  }
  return acc;
}

// ---------------------------------------------------------------------------
// Locale format helpers (unchanged)
// ---------------------------------------------------------------------------

bool LocalizedText::is_locale_format_valid(string_view locale)
{
  if (locale.empty())
  {
    return true;
  }

  if ((locale.size() < 2) || (locale.size() > 6))
  {
    return false;
  }

  bool charIsValid = utils::is_lower_case_ascii_letter(locale.data()[0]);
  if (!charIsValid)
  {
    return false;
  }
  charIsValid = utils::is_lower_case_ascii_letter(locale.data()[1]);
  if (!charIsValid)
  {
    return false;
  }

  if (locale.size() > 2)
  {
    if (locale.size() < 5)
    {
      return false;
    }
    if (locale.data()[2] != '-')
    {
      return false;
    }
    charIsValid = utils::is_upper_case_ascii_letter(locale.data()[3]);
    if (!charIsValid)
    {
      return false;
    }
    charIsValid = utils::is_upper_case_ascii_letter(locale.data()[4]);
    if (!charIsValid)
    {
      return false;
    }
    if (locale.size() == 6)
    {
      charIsValid = utils::is_upper_case_ascii_letter(locale.data()[5]);
      if (!charIsValid)
      {
        return false;
      }
    }
  }

  return true;
}

std::pair<String, String> LocalizedText::parse_locale_id(string_view locale)
{
  if (!is_locale_format_valid(locale))
  {
    return {};
  }

  constexpr size_t languageLength{2};
  size_t index{0};

  auto localeView = string_view{locale};
  auto language = localeView.substr(index, languageLength);
  index += languageLength;

  string_view region;
  if ((localeView.size() > index) && (localeView.at(index) == '-'))
  {
    index++;
    region = localeView.substr(index, localeView.size() - index);
  }

  return {language, region};
}

BuiltInTypeId LocalizedText::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::LocalizedText};
}

}  // namespace ua
