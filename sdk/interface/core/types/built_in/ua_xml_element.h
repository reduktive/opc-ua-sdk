// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA XmlElement built-in type: a serialized XML fragment.
/// @ingroup core_types

#ifndef UA_XML_ELEMENT_H
#define UA_XML_ELEMENT_H

#include "ua_built_in_types_fwd_decl.h"

namespace ua
{

/// The OPC UA `XmlElement` built-in type: an XML fragment held as serialized text.
///
/// Owns its serialized markup in a backing `std::string`, so copies are deep and
/// independent. The text is the raw XML as it appears on the wire; this type does
/// not parse or validate the markup. Constructs implicitly from `string_view` and
/// `std::string`, and converts implicitly back to a `string_view`, so an
/// XmlElement is usable wherever standard text is expected.
/// @ingroup core_types
class XmlElement
{
public:
  /// Constructs the empty XmlElement.
  XmlElement() = default;

  /// Copy-constructs, deep-copying the serialized text.
  XmlElement(const XmlElement&) = default;

  /// Move-constructs; the source is left in a valid but unspecified state.
  /// @param other The XmlElement to move from.
  XmlElement(XmlElement&& other) noexcept = default;

  /// Copy-assigns, deep-copying the serialized text.
  /// @param other The XmlElement to copy from.
  /// @return Reference to this XmlElement.
  XmlElement& operator=(const XmlElement& other) = default;

  /// Move-assigns; the source is left in a valid but unspecified state.
  /// @param other The XmlElement to move from.
  /// @return Reference to this XmlElement.
  XmlElement& operator=(XmlElement&& other) noexcept = default;

  /// Destroys the XmlElement, releasing its serialized text.
  ~XmlElement() = default;

  /// Replaces this XmlElement's contents by taking ownership of @p other.
  ///
  /// @param other The XML text to move from.
  /// @return Reference to this XmlElement.
  XmlElement& operator=(std::string other);

  /// Replaces this XmlElement's contents with a copy of the text viewed by @p other.
  ///
  /// @param other The XML text to copy.
  /// @return Reference to this XmlElement.
  XmlElement& operator=(string_view other);

  /// Compares two XmlElements for byte-wise equality of their serialized text.
  /// @return `true` if both XmlElements hold byte-wise identical serialized text; `false` otherwise.
  bool operator==(const XmlElement&) const = default;

  /// Returns a non-owning view over this XmlElement's serialized text.
  ///
  /// @warning The view is invalidated by any mutation of, or the destruction of,
  ///          this XmlElement.
  operator string_view() const
  {
    return mValue;
  }

  /// Returns `true` if this XmlElement holds no text.
  /// @return `true` if this XmlElement holds no text; `false` otherwise.
  bool empty() const;

  /// Resets this XmlElement to the empty value.
  void clear();

  /// Returns the OPC UA built-in type identifier for XmlElement.
  ///
  /// @return @ref BuiltInTypeId for this type.
  static BuiltInTypeId built_in_type_id();

  /// Returns a read-only reference to this XmlElement's serialized text.
  ///
  /// @warning The reference is invalidated by any mutation of, or the destruction
  ///          of, this XmlElement.
  /// @return Const reference to the serialized XML text.
  const std::string& value() const;

  /// Returns a mutable reference to this XmlElement's serialized text.
  ///
  /// @warning The reference is invalidated by any reassignment of, or the
  ///          destruction of, this XmlElement.
  /// @return Mutable reference to the serialized XML text.
  std::string& value();

private:
  std::string mValue;
};

/// Returns the OPC UA type name `"XmlElement"` for `XmlElement`.
///
/// Explicit specialisation of the `get_typename` primary template.
/// @return The type name `"XmlElement"`.
template<>
inline string_view get_typename<XmlElement>()
{
  return "XmlElement";
}

}  // namespace ua

#endif  // !UA_XML_ELEMENT_H
