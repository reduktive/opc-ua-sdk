// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TO_STRING_H
#define UA_TO_STRING_H

/// @file
/// @brief Human-readable string formatting for OPC UA built-in types.
/// @ingroup core_types

#include <string>
#include "ua_attribute_id.h"
#include "ua_variant.h"
#include "ua_data_value.h"
#include "ua_status_to_string.h"

namespace ua
{

/// @defgroup core_types_to_string to_string formatting
/// @ingroup core_types
///
/// Synchronous, allocation-returning formatters that render OPC UA built-in
/// types to a diagnostic, human-readable @c std::string.
///
/// The output is intended for logs, test failure messages, and debugging - it
/// is **not** a wire format and is not guaranteed stable across releases; do not
/// parse it. Every overload is pure and synchronous, copies into a freshly
/// allocated string, and never throws. Composite values (@ref Variant, @ref
/// DataValue, @ref DiagnosticInfo, @ref Structure, and @ref Array) accept an
/// @c indent argument controlling pretty-printing, and have a compact companion
/// in @ref to_summary_string.
/// @{

/// Formats a boolean as @c "true" or @c "false".
/// @param value Boolean to format.
/// @return @c "true" or @c "false".
std::string to_string(bool value);
/// Formats a signed 8-bit integer in decimal.
/// @param value Signed 8-bit integer to format.
/// @return The decimal text of @p value.
std::string to_string(int8_t value);
/// Formats an unsigned 8-bit integer in decimal.
/// @param value Unsigned 8-bit integer to format.
/// @return The decimal text of @p value.
std::string to_string(uint8_t value);
/// Formats a signed 16-bit integer in decimal.
/// @param value Signed 16-bit integer to format.
/// @return The decimal text of @p value.
std::string to_string(int16_t value);
/// Formats an unsigned 16-bit integer in decimal.
/// @param value Unsigned 16-bit integer to format.
/// @return The decimal text of @p value.
std::string to_string(uint16_t value);
/// Formats a signed 32-bit integer in decimal.
/// @param value Signed 32-bit integer to format.
/// @return The decimal text of @p value.
std::string to_string(int32_t value);
/// Formats an unsigned 32-bit integer in decimal.
/// @param value Unsigned 32-bit integer to format.
/// @return The decimal text of @p value.
std::string to_string(uint32_t value);
/// Formats a signed 64-bit integer in decimal.
/// @param value Signed 64-bit integer to format.
/// @return The decimal text of @p value.
std::string to_string(int64_t value);
/// Formats an unsigned 64-bit integer in decimal.
/// @param value Unsigned 64-bit integer to format.
/// @return The decimal text of @p value.
std::string to_string(uint64_t value);
/// Formats a single-precision float.
/// @param value Single-precision float to format.
/// @return The formatted text of @p value.
std::string to_string(float value);
/// Formats a double-precision float.
/// @param value Double-precision float to format.
/// @return The formatted text of @p value.
std::string to_string(double value);
/// Formats a UA @ref String as its UTF-8 text.
/// @param value @ref String to format.
/// @return The UTF-8 text of @p value.
std::string to_string(const String& value);
/// Formats a @ref DateTime as an ISO 8601 timestamp.
/// @param value @ref DateTime to format.
/// @return The ISO 8601 timestamp text of @p value.
std::string to_string(const DateTime& value);
/// Formats a @ref Guid in canonical brace-less hyphenated form.
/// @param value @ref Guid to format.
/// @return The canonical hyphenated text of @p value.
std::string to_string(const Guid& value);
/// Formats a @ref ByteString as standard base64 (RFC 4648), the form the SDK also uses when a byte
/// string is folded into an @ref ErrorDetail context fact, so the two are directly comparable.
/// @param value @ref ByteString to format.
/// @return The base64 text of @p value.
std::string to_string(const ByteString& value);
/// Formats an @ref XmlElement as its raw XML text.
/// @param value @ref XmlElement to format.
/// @return The raw XML text of @p value.
std::string to_string(const XmlElement& value);
/// Formats a @ref NodeId in the canonical @c "ns=...;..." textual notation.
/// @param value @ref NodeId to format.
/// @return The canonical @c "ns=...;..." text of @p value.
std::string to_string(const NodeId& value);
/// Formats an @ref ExpandedNodeId, including its namespace URI and server index.
/// @param value @ref ExpandedNodeId to format.
/// @return The textual notation of @p value, including namespace URI and server index.
std::string to_string(const ExpandedNodeId& value);
/// Formats a @ref StatusCode as its symbolic name.
/// @param value @ref StatusCode to format.
/// @return The symbolic name of @p value.
std::string to_string(const StatusCode& value);
/// Formats a @ref QualifiedName as @c "ns:name".
/// @param value @ref QualifiedName to format.
/// @return The @c "ns:name" text of @p value.
std::string to_string(const QualifiedName& value);
/// Formats a @ref LocalizedText as its text, with locale where present.
/// @param value @ref LocalizedText to format.
/// @return The text of @p value, with locale where present.
std::string to_string(const LocalizedText& value);

/// Formats a @ref Variant, expanding scalars, arrays, and nested structures.
///
/// Renders the contained value according to its built-in type. Arrays and nested
/// structures are expanded element by element; use @ref to_summary_string for a
/// compact, size-only rendering of large arrays.
///
/// @param value  Variant to render.
/// @param indent Indentation width in spaces for pretty-printing. @c 0 (the
///               default) produces a single-line rendering; a positive value
///               emits a multi-line, indented layout nested at that column.
/// @return The rendered text.
/// @see to_summary_string
std::string to_string(const Variant& value, int indent = 0);

/// Formats a @ref DataValue, including its value, status, and timestamps.
///
/// @param value  DataValue to render.
/// @param indent Indentation width in spaces; @c 0 (the default) renders on a
///               single line, a positive value emits a multi-line layout.
/// @return The rendered text.
/// @see to_summary_string
std::string to_string(const DataValue& value, int indent = 0);

/// Formats a @ref DiagnosticInfo, including any nested inner diagnostics.
///
/// @param value  DiagnosticInfo to render.
/// @param indent Indentation width in spaces; @c 0 (the default) renders on a
///               single line, a positive value emits a multi-line layout.
/// @return The rendered text.
/// @see to_summary_string
std::string to_string(const DiagnosticInfo& value, int indent = 0);

/// Formats a @ref Decimal in its full textual decimal representation.
/// @param value @ref Decimal to format.
/// @return The full decimal text of @p value.
std::string to_string(const Decimal& value);
/// Formats a @ref BuiltInTypeId as its type name (e.g. @c "Int32").
/// @param value @ref BuiltInTypeId to format.
/// @return The type name of @p value.
std::string to_string(BuiltInTypeId value);
/// Formats an @c AttributeId as its attribute name (e.g. @c "Value").
/// @param value @c AttributeId to format.
/// @return The attribute name of @p value.
std::string to_string(AttributeId value);

/// Formats a @ref Structure via its own @ref Structure::to_string.
///
/// @param value  Structure to render.
/// @param indent Indentation width in spaces; @c 0 (the default) renders on a
///               single line, a positive value emits a multi-line layout.
/// @return The rendered text.
inline std::string to_string(const Structure& value, int indent = 0)
{
  return value.to_string(indent);
}

/// Formats an @ref Array, expanding every element.
///
/// Renders each element with the matching scalar @ref to_string overload, or -
/// for arrays of structures - each structure's own @ref Structure::to_string.
/// Empty arrays render as @c "Array[]"; null structure elements render as
/// @c "null".
///
/// @tparam T     Element type of the array.
/// @param value  Array to render.
/// @param indent Indentation width in spaces. @c 0 (the default) renders the
///               whole array on a single line; for arrays of structures a
///               positive value emits a multi-line, indented layout (it is
///               ignored for scalar element types).
/// @return The rendered text.
template<typename T>
std::string to_string(const Array<T>& value, int indent = 0)
{
  if constexpr (std::is_same_v<T, RefStructure<Structure>>)
  {
    if (indent > 0)
    {
      if (value.empty())
      {
        return "Array[]";
      }
      const std::string pad(numeric_cast<size_t>(indent), ' ');
      const std::string innerPad(numeric_cast<size_t>(indent + 2), ' ');
      std::string result = "Array[\n";
      const auto& payload = value.payload();
      for (size_t i = 0; i < payload.size(); ++i)
      {
        if (i > 0)
        {
          result += ",\n";
        }
        result += innerPad;
        result += payload[i] ? payload[i]->to_string(indent + 2) : "null";
      }
      result += "\n";
      result += pad;
      result += "]";
      return result;
    }
    std::string result = "Array[";
    const auto& payload = value.payload();
    for (size_t i = 0; i < payload.size(); ++i)
    {
      if (i > 0)
      {
        result += ", ";
      }
      result += payload[i] ? payload[i]->to_string(0) : "null";
    }
    result += "]";
    return result;
  }
  else
  {
    (void)indent;
    std::string result = "Array[";
    const auto& payload = value.payload();
    for (size_t i = 0; i < payload.size(); ++i)
    {
      if (i > 0)
      {
        result += ", ";
      }
      if constexpr (std::is_same_v<T, bool>)
      {
        result += to_string(static_cast<bool>(payload[i]));
      }
      else
      {
        result += to_string(payload[i]);
      }
    }
    result += "]";
    return result;
  }
}

/// Formats a @ref Variant compactly, summarising arrays by size.
///
/// Like @ref to_string but renders arrays as a type-and-count summary (e.g.
/// @c "Array<Int32>[5 elements]") rather than expanding every element. Scalars
/// are rendered the same as @ref to_string. Always single-line. Never throws.
///
/// @param value Variant to summarise.
/// @return The compact, single-line rendering of @p value.
/// @see to_string
std::string to_summary_string(const Variant& value);

/// Formats a @ref DataValue compactly, summarising its array value by size.
///
/// @param value DataValue to summarise.
/// @return The compact, single-line rendering of @p value.
/// @see to_string, to_summary_string(const Variant&)
std::string to_summary_string(const DataValue& value);

/// Formats a @ref DiagnosticInfo compactly.
///
/// @param value DiagnosticInfo to summarise.
/// @return The compact, single-line rendering of @p value.
/// @see to_string, to_summary_string(const Variant&)
std::string to_summary_string(const DiagnosticInfo& value);

/// @}

/// @name ErrorDetail context-value renderers
/// Found by ADL from `ErrorDetailBuilder::context(ContextKey, const T&)` so a raw
/// value can be passed to `.context(...)` instead of a hand-written `to_string`.
/// Each delegates to the canonical `to_string` (which is the documented value-format
/// for these keys). Deliberately NOT provided for StatusCode -- a status threads
/// through `.cause(...)`, never a context fact (one-fact-one-home).
/// @{

/// Renders a `NodeId` for an ErrorDetail context fact, via `to_string`.
/// @param value `NodeId` to render as a context fact.
/// @return The rendered text of @p value.
[[nodiscard]] inline std::string error_detail_render(const NodeId& value)
{
  return to_string(value);
}

/// Renders an `ExpandedNodeId` for an ErrorDetail context fact, via `to_string`.
/// @param value `ExpandedNodeId` to render as a context fact.
/// @return The rendered text of @p value.
[[nodiscard]] inline std::string error_detail_render(const ExpandedNodeId& value)
{
  return to_string(value);
}

/// Renders a `QualifiedName` for an ErrorDetail context fact, via `to_string`.
/// @param value `QualifiedName` to render as a context fact.
/// @return The rendered text of @p value.
[[nodiscard]] inline std::string error_detail_render(const QualifiedName& value)
{
  return to_string(value);
}

/// Renders an @c AttributeId for an ErrorDetail context fact, via `to_string`.
/// @param value @c AttributeId to render as a context fact.
/// @return The rendered text of @p value.
[[nodiscard]] inline std::string error_detail_render(AttributeId value)
{
  return to_string(value);
}

/// @}

}  // namespace ua

#endif  // UA_TO_STRING_H
