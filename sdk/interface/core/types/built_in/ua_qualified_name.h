// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A namespace-qualified name, as defined by OPC 10000-6.
/// @ingroup core_types

#ifndef UA_QUALIFIED_NAME_H
#define UA_QUALIFIED_NAME_H

#include <compare>
#include "ua_built_in_types_fwd_decl.h"
#include "ua_result.h"
#include "ua_string.h"

namespace ua
{

/// A name qualified by a namespace, as defined by OPC 10000-6.
///
/// A QualifiedName pairs a @ref name() with the @ref namespace_index() of the
/// namespace table entry that scopes it, so the same text can be reused in
/// different namespaces without collision. It is most commonly used for
/// BrowseNames. A default-constructed QualifiedName has namespace index `0` and
/// a null @ref name(), which is the null value reported by @ref is_null().
/// @ingroup core_types
class QualifiedName
{
public:
  /// Constructs a null QualifiedName with namespace index `0` and a null name.
  QualifiedName() = default;

  /// Copy-constructs, deep-copying the name text.
  ///
  /// @param other The QualifiedName to copy.
  QualifiedName(const QualifiedName& other) = default;

  /// Move-constructs; the source is left in a valid but unspecified state.
  ///
  /// @param other The QualifiedName to move from; left in a valid but unspecified state.
  QualifiedName(QualifiedName&& other) noexcept = default;

  /// Copy-assigns, deep-copying the name text.
  ///
  /// @param other The QualifiedName to copy.
  /// @return Reference to this QualifiedName.
  QualifiedName& operator=(const QualifiedName& other) = default;

  /// Move-assigns; the source is left in a valid but unspecified state.
  ///
  /// @param other The QualifiedName to move from; left in a valid but unspecified state.
  /// @return Reference to this QualifiedName.
  QualifiedName& operator=(QualifiedName&& other) noexcept = default;

  /// Destroys the QualifiedName, releasing its name text.
  ~QualifiedName() = default;

  /// Constructs a QualifiedName in namespace `0` with the given name text.
  ///
  /// Does not parse: `QualifiedName{"2:Foo"}` is the namespace-0 name `2:Foo`. Use @ref parse for text
  /// that carries a namespace index.
  ///
  /// @param name Name text; copied into the QualifiedName.
  explicit QualifiedName(string_view name);

  /// Constructs a QualifiedName in the given namespace with the given name text.
  ///
  /// @param namespaceIndex Index into the server namespace table that scopes the name.
  /// @param name           Name text; copied into the QualifiedName.
  QualifiedName(uint16_t namespaceIndex, string_view name);

  /// Compares two QualifiedNames for equality of namespace index and name.
  ///
  /// @param obj The QualifiedName to compare against.
  /// @return `true` if both the namespace index and the name are equal.
  bool operator==(const QualifiedName& obj) const = default;

  /// Orders by @ref namespace_index() first, then by @ref name().
  ///
  /// @param other The QualifiedName to compare against.
  /// @return The ordering of this QualifiedName relative to @p other.
  std::strong_ordering operator<=>(const QualifiedName& other) const;

  /// Returns the index of the namespace that scopes the name.
  ///
  /// @return The namespace index that scopes the name.
  uint16_t namespace_index() const;

  /// Returns a mutable reference to the namespace index.
  ///
  /// @return A mutable reference to the namespace index.
  /// @see namespace_index() const
  uint16_t& namespace_index();

  /// Returns the name text.
  ///
  /// @return The name text.
  const String& name() const;

  /// Returns a mutable reference to the name text.
  ///
  /// @return A mutable reference to the name text.
  /// @see name() const
  String& name();

  /// Returns whether this is the null value (a null @ref name()).
  ///
  /// The namespace index does not affect nullness: any namespace index with a
  /// null name is null.
  ///
  /// @return `true` if the name is null.
  bool is_null() const;

  /// Resets to the null value (namespace index `0` and a null name).
  void clear();

  /// Returns a hash of the namespace index and name, suitable for hashed containers.
  ///
  /// Consistent with @ref operator==: equal QualifiedNames hash equally.
  ///
  /// @return A hash of the namespace index and name.
  size_t hash() const;

  /// Returns the OPC UA built-in type identifier for QualifiedName.
  ///
  /// @return @ref BuiltInTypeId for this type.
  static BuiltInTypeId built_in_type_id();

  /// Parses the text @ref ua::to_string writes for a QualifiedName, the OPC 10000-4 Annex A form
  /// `[namespace-index:]name`: an optional decimal namespace index and colon, then the name, in
  /// which each reserved character (slash, dot, angle bracket, colon, number sign, exclamation mark or
  /// ampersand) is preceded by an ampersand. Without a prefix the
  /// namespace is 0. `parse(to_string(name)) == name` for every QualifiedName; `2&:Foo` is the
  /// namespace-0 name `2:Foo`, and `2:Foo` is `Foo` in namespace 2.
  ///
  /// @param text The textual QualifiedName.
  /// @return The QualifiedName @p text names.
  /// @throws UaException with @ref Status::BadDecodingError if @p text has an unescaped reserved
  ///         character in its name, an `&` not followed by a reserved character, or a namespace index
  ///         above 65535.
  /// @see try_parse
  static QualifiedName parse(string_view text);

  /// Parses like @ref parse and reports a malformed text as a bad result instead of throwing.
  ///
  /// @param text The textual QualifiedName.
  /// @return The QualifiedName, or Bad_DecodingError with an @ref ErrorDetail naming the fault.
  [[nodiscard]] static QualifiedNameResult try_parse(string_view text) noexcept;

private:
  uint16_t mNamespaceIndex{0};
  String mName;
};

/// Returns the OPC UA type name `"QualifiedName"` for `QualifiedName`.
///
/// Explicit specialisation of the `get_typename` primary template.
///
/// @return The type-name string view `"QualifiedName"`.
template<>
inline string_view get_typename<QualifiedName>()
{
  return "QualifiedName";
}

}  // namespace ua

/// `std::hash` specialisation enabling @ref ua::QualifiedName as a hashed-container key.
///
/// Forwards to @ref ua::QualifiedName::hash().
template<>
struct std::hash<ua::QualifiedName>
{
  /// Returns the hash of @p obj via @ref ua::QualifiedName::hash().
  ///
  /// @param obj The QualifiedName to hash.
  /// @return The hash of @p obj.
  size_t operator()(const ua::QualifiedName& obj) const noexcept
  {
    return obj.hash();
  }
};

#endif  // !UA_QUALIFIED_NAME_H
