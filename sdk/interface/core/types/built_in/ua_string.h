// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA String built-in type: a UTF-8 text value.
/// @ingroup core_types

#ifndef UA_STRING_H
#define UA_STRING_H

#include <compare>
#include "ua_includes.h"
#include "ua_built_in_type_id.h"
#include "ua_built_in_types_fwd_decl.h"

namespace ua
{

/// The OPC UA `String` built-in type: a sequence of UTF-8 encoded characters.
///
/// Owns its character data in a backing `std::string`, so copies are deep and
/// independent. Constructs implicitly from `const char*`, `string_view`, and
/// `std::string`, and converts implicitly back to either of those view/string
/// forms, so a String is usable wherever standard text is expected. As defined
/// by OPC 10000-6, the null String and the empty String share the same value in
/// this representation; @ref is_null() and @ref empty() are therefore
/// equivalent. Constructing from a null `const char*` yields the empty value.
/// @ingroup core_types
class String
{
public:
  /// Constructs the empty (null) String.
  String() = default;

  /// Copy-constructs, deep-copying the character data.
  String(const String&) = default;

  /// Move-constructs; the source is left in a valid but unspecified state.
  ///
  /// @param other The String to move from; left in a valid but unspecified state.
  String(String&& other) noexcept = default;

  /// Copy-assigns, deep-copying the character data.
  ///
  /// @param other The String to copy.
  /// @return Reference to this String.
  String& operator=(const String& other) = default;

  /// Move-assigns; the source is left in a valid but unspecified state.
  ///
  /// @param other The String to move from; left in a valid but unspecified state.
  /// @return Reference to this String.
  String& operator=(String&& other) noexcept = default;

  /// Destroys the String, releasing its character data.
  ~String() = default;

  /// Constructs a String from a null-terminated C string.
  ///
  /// @param value The text to copy; a null pointer yields the empty String.
  String(const char* value);

  /// Constructs a String by copying the characters viewed by @p value.
  ///
  /// @param value The text to copy.
  String(string_view value);

  /// Constructs a String by copying @p value.
  ///
  /// @param value The text to copy.
  String(const std::string& value);

  /// Replaces this String's contents with a copy of @p other.
  ///
  /// @param other The text to copy.
  /// @return Reference to this String.
  String& operator=(const std::string& other);

  /// Replaces this String's contents with a copy of the characters viewed by @p other.
  ///
  /// @param other The text to copy.
  /// @return Reference to this String.
  String& operator=(string_view other);

  /// Replaces this String's contents with a copy of the null-terminated C string @p other.
  ///
  /// @param other The text to copy; a null pointer yields the empty String.
  /// @return Reference to this String.
  String& operator=(const char* other);

  /// Compares two Strings for byte-wise equality of their characters.
  ///
  /// @return `true` if both Strings hold the same sequence of character bytes.
  bool operator==(const String&) const = default;

  /// Orders two Strings lexicographically by their character bytes.
  ///
  /// @return The ordering of this String relative to the other.
  auto operator<=>(const String&) const = default;

  /// Returns a non-owning view over this String's characters.
  ///
  /// @return A view over this String's UTF-8 character bytes.
  /// @warning The view is invalidated by any mutation of, or the destruction of,
  ///          this String.
  operator string_view() const;

  /// Returns a copy of this String's characters as a `std::string`.
  ///
  /// @return A `std::string` copy of this String's characters.
  operator std::string() const;

  /// Returns `true` if this String holds no characters.
  ///
  /// @return `true` if this String holds no characters.
  /// @see is_null
  bool empty() const;

  /// Returns `true` if this is the null String.
  ///
  /// Equivalent to @ref empty(): the null and empty Strings share one value in
  /// this representation.
  ///
  /// @return `true` if this is the null String.
  /// @see empty
  bool is_null() const;

  /// Returns the number of UTF-8 code units (bytes) in this String.
  ///
  /// @return The number of UTF-8 code units (bytes) in this String.
  size_t size() const;

  /// Resets this String to the empty (null) value.
  void clear();

  /// Returns the OPC UA built-in type identifier for String.
  ///
  /// @return @ref BuiltInTypeId for this type.
  static BuiltInTypeId built_in_type_id();

private:
  std::string mValue;
};

/// Returns a hash of @p s suitable for use in unordered containers.
///
/// @param s The String to hash.
/// @return A hash of @p s suitable for use in unordered containers.
/// @see std::hash<ua::String>
size_t hash_value(const String& s);

/// Returns the OPC UA type name `"String"` for `String`.
///
/// Explicit specialisation of the `get_typename` primary template.
///
/// @return The type-name string view `"String"`.
template<>
inline string_view get_typename<String>()
{
  return "String";
}

}  // namespace ua

/// `std::hash` specialisation for @ref ua::String.
///
/// Enables use of @ref ua::String as a key in `std::unordered_map` and
/// `std::unordered_set`; delegates to @ref ua::hash_value().
template<>
struct std::hash<ua::String>
{
  /// Returns the hash of @p s.
  ///
  /// @param s The String to hash.
  /// @return The hash of @p s.
  size_t operator()(const ua::String& s) const noexcept
  {
    return hash_value(s);
  }
};

#endif  // !UA_STRING_H
