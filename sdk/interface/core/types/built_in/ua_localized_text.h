// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Rich `LocalizedText` built-in type with multi-translation aggregate storage.
/// @ingroup core_types

#ifndef UA_LOCALIZED_TEXT_H
#define UA_LOCALIZED_TEXT_H

#include <utility>
#include <variant>
#include <vector>

#include "ua_built_in_types_fwd_decl.h"
#include "ua_locale_id.h"

namespace ua
{

/// A human-readable text value tagged with a locale, optionally carrying several translations.
///
/// The OPC UA wire form of a LocalizedText is a single `{locale, text}` pair, but
/// server-side storage may hold several translations of the same text for one node.
/// This type normalises between two internal representations: a *scalar* case (a single
/// `{locale, text}` pair) and a shared *aggregate* (two or more translations held behind a
/// `shared_ptr`). Copies of a multi-translation value stay O(1), and callers that only deal
/// with the single-translation case never pay for the aggregate apparatus.
///
/// Locale resolution - collapsing an aggregate to the scalar appropriate for a given session
/// - is driven by @ref resolve. A default-constructed value is scalar-empty (see @ref is_null).
///
/// @ingroup core_types
class LocalizedText
{
public:
  /// A single `{locale, text}` translation pair.
  using Scalar = std::pair<LocaleId, String>;

  /// Constructs a scalar-empty value (empty locale and empty text).
  LocalizedText() = default;
  /// Copies @p other; an aggregate is shared by pointer, so the copy is O(1).
  /// @param other LocalizedText to copy.
  LocalizedText(const LocalizedText& other) = default;
  /// Move-constructs from @p other, leaving it scalar-empty.
  /// @param other LocalizedText to move from; left scalar-empty.
  LocalizedText(LocalizedText&& other) noexcept = default;
  /// Copy-assigns @p other; an aggregate is shared by pointer, so the copy is O(1).
  /// @param other LocalizedText to copy.
  /// @return Reference to this LocalizedText.
  LocalizedText& operator=(const LocalizedText& other) = default;
  /// Move-assigns from @p other, leaving it scalar-empty.
  /// @param other LocalizedText to move from; left scalar-empty.
  /// @return Reference to this LocalizedText.
  LocalizedText& operator=(LocalizedText&& other) noexcept = default;
  /// Destroys the value, releasing any shared aggregate storage.
  ~LocalizedText() = default;

  /// Constructs a scalar value from an explicit locale and text.
  /// @param locale Locale identifier for the translation.
  /// @param text   Text of the translation.
  LocalizedText(LocaleId locale, String text);

  /// Constructs a scalar value with the given text and an empty locale.
  /// @param text Text of the translation; the locale is left empty.
  explicit LocalizedText(String text);

  /// Builds a value from a list of translations, choosing scalar or aggregate storage.
  ///
  /// Zero entries collapse to a scalar-empty value; a single entry collapses to a scalar;
  /// two or more entries are stored as a shared aggregate.
  ///
  /// @param translations Translation pairs, in insertion order (the first entry becomes the
  ///                     canonical scalar view).
  /// @return The normalised value.
  static LocalizedText from_translations(std::vector<Scalar> translations);

  /// Returns the canonical locale - on an aggregate, the first-inserted entry's locale.
  ///
  /// Intended for client code holding a scalar wire value and for diagnostic / logging paths
  /// on the server. Server production code that needs locale-correct text must instead go
  /// through @ref resolve with the session's locales.
  ///
  /// @return The canonical locale.
  /// @see text, resolve
  const LocaleId& locale() const;

  /// Returns the canonical text - on an aggregate, the first-inserted entry's text.
  ///
  /// @return The canonical text.
  /// @see locale, resolve
  const String& text() const;

  /// Returns a mutable reference to the scalar locale for in-place assignment.
  ///
  /// Exists so scalar-producing paths (wire decoders, test fixtures, client builders) can
  /// assign via `lt.locale() = ...` without a fresh construction. Mutating an aggregate has
  /// no well-defined meaning (which translation?), so callers that may hold an aggregate must
  /// use @ref with_translation / @ref merged_with instead.
  ///
  /// @return A mutable reference to the scalar locale.
  /// @pre @ref is_scalar() is true; the precondition is asserted.
  /// @see text(), with_translation
  LocaleId& locale();

  /// Returns a mutable reference to the scalar text for in-place assignment.
  ///
  /// @return A mutable reference to the scalar text.
  /// @pre @ref is_scalar() is true; the precondition is asserted.
  /// @see locale(), with_translation
  String& text();

  /// Returns true if the value is stored as a single `{locale, text}` pair.
  ///
  /// Mutually exclusive with @ref is_aggregate. A default-constructed or cleared value is
  /// scalar (and scalar-empty).
  ///
  /// @return True if the value is stored as a single `{locale, text}` pair.
  bool is_scalar() const noexcept;

  /// Returns true if the value holds two or more translations in shared aggregate storage.
  ///
  /// Mutually exclusive with @ref is_scalar.
  ///
  /// @return True if the value holds two or more translations in shared aggregate storage.
  bool is_aggregate() const noexcept;

  /// Returns the number of translations held (0 for scalar-empty, 1 for scalar, >= 2 for an
  /// aggregate).
  /// @return The number of translations held.
  std::size_t translation_count() const noexcept;

  /// Returns the text for an exact locale match, or nullopt if no translation carries it.
  ///
  /// @param locale Locale identifier to match exactly (no fallback or language-only matching).
  /// @return The matching text, or nullopt if absent.
  /// @see resolve
  std::optional<String> text_for_locale(string_view locale) const;

  /// Returns a flat snapshot of all translations as `Scalar` pairs.
  ///
  /// A scalar-empty receiver yields an empty vector; a non-empty scalar yields a single-element
  /// vector; an aggregate yields the full translation list (a copy of the shared storage).
  /// Intended for adapter layers that need to iterate every translation; production read-path
  /// callers should use @ref resolve instead.
  ///
  /// @return A snapshot vector of all translations as `Scalar` pairs.
  std::vector<Scalar> translations() const;

  /// Returns a copy with `text` set for `locale`, leaving the receiver untouched.
  ///
  /// This builder never deletes: passing an empty `text` stores an explicit empty-string
  /// translation for that locale. For delete semantics use @ref without_translation, or
  /// @ref merged_with with an empty-text update (the spec 5.10.4 upsert path).
  ///
  /// @param locale Locale to upsert.
  /// @param text   Text to store (empty stores an explicit empty translation, not a deletion).
  /// @return A new value with the translation applied.
  LocalizedText with_translation(LocaleId locale, String text) const;

  /// Returns a copy with the given locale removed, leaving the receiver untouched.
  ///
  /// @param locale Locale to remove; a no-op if the receiver carries no such translation.
  /// @return A new value, normalised to scalar if the removal leaves fewer than two entries.
  LocalizedText without_translation(string_view locale) const;

  /// Returns a copy merged with `update` per spec 5.10.4 client-write semantics.
  ///
  /// The merge follows the spec's per-pair rules:
  /// - `{empty locale, empty text}` clears all translations (result is empty);
  /// - `{locale, empty text}` removes that locale from the receiver;
  /// - `{locale, non-empty text}` upserts `(locale, text)`.
  ///
  /// The receiver is untouched.
  ///
  /// @param update The incoming client write to apply.
  /// @return A new merged value.
  /// @see with_translation, without_translation
  LocalizedText merged_with(const LocalizedText& update) const;

  /// Resolves to the canonical scalar with no session context or server default.
  ///
  /// Falls back directly to the first-inserted entry; intended for diagnostic / logging paths.
  /// A scalar receiver takes a fast path and is returned unchanged with no allocation.
  ///
  /// @return A value for which @ref is_scalar() is true.
  /// @see resolve(span<const LocaleId>) const,
  ///      resolve(span<const LocaleId>, const LocaleId&) const
  LocalizedText resolve() const;

  /// Resolves to the best-matching scalar for the given session locales.
  ///
  /// A scalar receiver takes a fast path and is returned unchanged with no allocation.
  ///
  /// @param locales Session-preferred locales, in priority order.
  /// @return A value for which @ref is_scalar() is true.
  /// @see resolve() const, resolve(span<const LocaleId>, const LocaleId&) const
  LocalizedText resolve(span<const LocaleId> locales) const;

  /// Resolves to the best-matching scalar for the session locales plus a server-wide default.
  ///
  /// A scalar receiver takes a fast path and is returned unchanged with no allocation.
  ///
  /// @param locales       Session-preferred locales, in priority order.
  /// @param defaultLocale Server-wide default locale, tried after the session locales.
  /// @return A value for which @ref is_scalar() is true.
  /// @see resolve() const, resolve(span<const LocaleId>) const
  LocalizedText resolve(span<const LocaleId> locales, const LocaleId& defaultLocale) const;

  /// Compares two values for equality across their full translation sets.
  /// @return True if both values carry the same set of translations.
  friend bool operator==(const LocalizedText&, const LocalizedText&);

  /// Returns true if the value is scalar-empty (empty locale and empty text, no aggregate).
  /// @return True if the value is scalar-empty.
  bool is_null() const;

  /// Resets the value to scalar-empty.
  void clear();

  /// Returns true if `locale` is a syntactically valid OPC UA locale identifier.
  ///
  /// @param locale Candidate locale string (e.g. `"en"`, `"en-US"`).
  /// @return True if `locale` is a syntactically valid OPC UA locale identifier.
  static bool is_locale_format_valid(string_view locale);

  /// Splits a locale identifier into its `{language, region}` components.
  ///
  /// @param locale Locale string to parse (e.g. `"en-US"`).
  /// @return The `{language, region}` pair; the region is empty when none is present.
  static std::pair<String, String> parse_locale_id(string_view locale);

  /// Returns the OPC UA built-in type identifier for `LocalizedText`.
  /// @return The OPC UA built-in type identifier for `LocalizedText`.
  static BuiltInTypeId built_in_type_id();

private:
  using AggregateStorage = std::vector<Scalar>;
  using SharedAggregate = shared_ptr<const AggregateStorage>;

  // Invariant: a SharedAggregate in mRepresentation always has size >= 2.
  // Any collapse to zero or one entries normalises to the Scalar alternative.
  std::variant<Scalar, SharedAggregate> mRepresentation;

  const Scalar* scalar_ptr() const noexcept;
  const AggregateStorage* aggregate_ptr() const noexcept;

  // Reference accessor for the aggregate storage, used after a scalar_ptr()
  // check has established the representation is an aggregate. Encapsulates
  // the "not scalar => non-null aggregate" invariant in one place: returning
  // a reference (never null) lets -O2's -Wnull-dereference prove every
  // downstream deref is safe, and the explicit guard fail-stops if the
  // invariant is ever violated. Throws BadInternalError on a null handle.
  const AggregateStorage& aggregate_ref() const;

  friend size_t hash_value(const LocalizedText& lt) noexcept;
};

/// Computes a hash over the value's full translation set (Boost.Hash ADL entry point).
///
/// @param lt Value to hash.
/// @return A hash consistent with `LocalizedText::operator==`.
/// @note `noexcept`: `std::hash<LocalizedText>` is a noexcept hasher, so this must not throw.
///       A null aggregate handle (precluded by the representation invariant) hashes to `0`
///       rather than raising.
size_t hash_value(const LocalizedText& lt) noexcept;

/// Returns the SDK type name `"LocalizedText"`.
/// @return The SDK type name `"LocalizedText"`.
template<>
inline string_view get_typename<LocalizedText>()
{
  return "LocalizedText";
}

}  // namespace ua

/// `std::hash` specialization enabling use of @ref ua::LocalizedText as an unordered-container key.
template<>
struct std::hash<ua::LocalizedText>
{
  /// Returns the hash of `lt`, delegating to @ref ua::hash_value.
  /// @param lt Value to hash.
  /// @return The hash of `lt`.
  size_t operator()(const ua::LocalizedText& lt) const noexcept
  {
    return hash_value(lt);
  }
};

#endif  // !UA_LOCALIZED_TEXT_H
