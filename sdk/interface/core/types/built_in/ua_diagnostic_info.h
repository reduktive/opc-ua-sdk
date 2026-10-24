// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The built-in OPC UA DiagnosticInfo type and its accessors.
/// @ingroup core_types

#ifndef UA_DIAGNOSTIC_INFO_H
#define UA_DIAGNOSTIC_INFO_H

#include "ua_built_in_types_fwd_decl.h"
#include "ua_status_code.h"
#include "ua_string.h"

namespace ua
{

/// Optional diagnostic detail attached to a service or operation result.
///
/// Mirrors the OPC UA built-in DiagnosticInfo type (Part 4 / Part 6). The
/// four index fields (@ref symbolic_id, @ref namespace_uri, @ref locale,
/// @ref localized_text) are zero-based indices into the response's string
/// table, not strings themselves; they are only meaningful alongside the
/// table that produced them. A nested @ref inner_diagnostic_info forms a
/// chain that follows the corresponding chain of @ref inner_status_code
/// values back to the originating service.
///
/// Every field is optional: a default-constructed value carries no diagnostic
/// information (@ref is_null returns `true`) and encodes to the empty wire form.
///
/// @ingroup core_types
class DiagnosticInfo
{
public:
  /// Constructs a null DiagnosticInfo (no field set; @ref is_null is `true`).
  DiagnosticInfo() = default;
  /// Deep-copies @p other, cloning the whole @ref inner_diagnostic_info chain.
  /// @param other DiagnosticInfo to deep-copy.
  DiagnosticInfo(const DiagnosticInfo& other);
  /// Move-constructs from @p other, transferring its inner-diagnostic chain; @p other is left null.
  /// @param other DiagnosticInfo to move from; left null.
  DiagnosticInfo(DiagnosticInfo&& other) noexcept = default;
  /// Deep-copies @p other, cloning the whole @ref inner_diagnostic_info chain.
  /// @param other DiagnosticInfo to deep-copy.
  /// @return Reference to this DiagnosticInfo.
  DiagnosticInfo& operator=(const DiagnosticInfo& other);
  /// Move-assigns from @p other, transferring its inner-diagnostic chain; @p other is left null.
  /// @param other DiagnosticInfo to move from; left null.
  /// @return Reference to this DiagnosticInfo.
  DiagnosticInfo& operator=(DiagnosticInfo&& other) noexcept = default;
  /// Destroys the DiagnosticInfo, releasing its inner-diagnostic chain.
  ~DiagnosticInfo() = default;

  /// Compares all fields for equality, recursing into @ref inner_diagnostic_info.
  /// @param obj DiagnosticInfo to compare against.
  /// @return `true` when every field is equal, including the nested diagnostic chain.
  bool operator==(const DiagnosticInfo& obj) const;

  /// Index of the symbolic name in the response string table, if set.
  /// @return The symbolic-name index, or an empty optional when unset.
  const optional<int32_t>& symbolic_id() const;

  /// Mutable accessor for @ref symbolic_id.
  /// @return Mutable reference to the symbolic-name index optional.
  optional<int32_t>& symbolic_id();

  /// Index of the namespace URI in the response string table, if set.
  /// @return The namespace-URI index, or an empty optional when unset.
  const optional<int32_t>& namespace_uri() const;

  /// Mutable accessor for @ref namespace_uri.
  /// @return Mutable reference to the namespace-URI index optional.
  optional<int32_t>& namespace_uri();

  /// Index of the locale in the response string table, if set.
  /// @return The locale index, or an empty optional when unset.
  const optional<int32_t>& locale() const;

  /// Mutable accessor for @ref locale.
  /// @return Mutable reference to the locale index optional.
  optional<int32_t>& locale();

  /// Index of the localized text in the response string table, if set.
  /// @return The localized-text index, or an empty optional when unset.
  const optional<int32_t>& localized_text() const;

  /// Mutable accessor for @ref localized_text.
  /// @return Mutable reference to the localized-text index optional.
  optional<int32_t>& localized_text();

  /// Vendor-specific additional diagnostic text, if set.
  /// @return The additional diagnostic text, or an empty optional when unset.
  const optional<std::string>& additional_info() const;

  /// Mutable accessor for @ref additional_info.
  /// @return Mutable reference to the additional-info optional.
  optional<std::string>& additional_info();

  /// Status code of the inner (nested) operation, if this diagnostic wraps one.
  /// @return The inner status code, or an empty optional when there is none.
  const optional<StatusCode>& inner_status_code() const;

  /// Mutable accessor for @ref inner_status_code.
  /// @return Mutable reference to the inner-status-code optional.
  optional<StatusCode>& inner_status_code();

  /// Nested diagnostic for the inner operation, forming a diagnostic chain.
  ///
  /// Null when there is no further nesting. The pointee is owned by this object
  /// and shares its lifetime; copies of a DiagnosticInfo deep-copy the chain.
  ///
  /// @return The nested diagnostic, or a null pointer when there is no further nesting.
  const unique_ptr<DiagnosticInfo>& inner_diagnostic_info() const;

  /// Mutable accessor for @ref inner_diagnostic_info.
  /// @return Mutable reference to the nested-diagnostic owning pointer.
  unique_ptr<DiagnosticInfo>& inner_diagnostic_info();

  /// Returns `true` when no field is set, i.e. there is no diagnostic information.
  /// @return `true` when the object carries no diagnostic information.
  bool is_null() const;

  /// Returns `true` when at least one field is set.
  ///
  /// Equivalent to `!is_null()`.
  ///
  /// @return `true` when at least one field is set.
  bool is_not_null() const;

  /// Resets every field, returning the object to the null state.
  ///
  /// @post `is_null()` is `true`.
  void clear();

  /// Returns the built-in type identifier for DiagnosticInfo.
  /// @return @ref BuiltInTypeId for this type.
  static BuiltInTypeId built_in_type_id();

private:
  optional<int32_t> mSymbolicId;
  optional<int32_t> mNamespaceUri;
  optional<int32_t> mLocale;
  optional<int32_t> mLocalizedText;
  optional<std::string> mAdditionalInfo;
  optional<StatusCode> mInnerStatusCode;
  unique_ptr<DiagnosticInfo> mInnerDiagnosticInfo;

  void copy(const DiagnosticInfo& other);
};

/// Returns the type name `"DiagnosticInfo"` for the DiagnosticInfo specialization.
/// @return The literal `"DiagnosticInfo"`.
template<>
inline string_view get_typename<DiagnosticInfo>()
{
  return "DiagnosticInfo";
}

}  // namespace ua

#endif  // !UA_DIAGNOSTIC_INFO_H
