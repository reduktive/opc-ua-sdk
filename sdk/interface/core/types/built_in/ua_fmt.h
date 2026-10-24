// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief {fmt} formatter specializations for the OPC UA built-in types.
///
/// Including this header (`ua_client.h` and `ua_server.h` include it) makes the built-in types
/// usable with `fmt::format`, `fmt::print` and the SDK's `{}`-style logging: String, DateTime, Guid,
/// ByteString, XmlElement, NodeId, ExpandedNodeId, StatusCode, QualifiedName, LocalizedText, Variant,
/// DataValue and the other built-in types render as @ref ua::to_string writes them, and accept the
/// `std::string` format specifiers (width, alignment, fill). The specializations themselves are hidden
/// from the reference: Doxygen cannot resolve the scope of the external `fmt::formatter` template.
/// @ingroup core_types

#ifndef UA_FMT_H
#define UA_FMT_H

#include "fmt/format.h"
#include "ua_to_string.h"

/// @cond FMT_FORMATTER_SPECIALIZATIONS

/// {fmt} formatter for @ref ua::String.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, so the full set of `std::string` format
/// specifiers (width, alignment, fill) applies. Including this header makes
/// `ua::String` usable directly with `fmt::format`, `fmt::print`, and the
/// SDK's `{}`-style logging.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::String> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::String& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::DateTime.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::DateTime> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::DateTime& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::Guid.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::Guid> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::Guid& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::ByteString.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::ByteString> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::ByteString& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::XmlElement.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::XmlElement> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::XmlElement& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::NodeId.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::NodeId> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::NodeId& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::ExpandedNodeId.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::ExpandedNodeId> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::ExpandedNodeId& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::StatusCode.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::StatusCode> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::StatusCode& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::QualifiedName.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::QualifiedName> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::QualifiedName& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::LocalizedText.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::LocalizedText> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::LocalizedText& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::Variant.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::Variant> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::Variant& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::DataValue.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::DataValue> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::DataValue& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::DiagnosticInfo.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::DiagnosticInfo> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::DiagnosticInfo& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// {fmt} formatter for @ref ua::Decimal.
///
/// Renders the value via @ref ua::to_string and forwards to the
/// `std::string` formatter, inheriting its format specifiers.
/// @ingroup core_types
template<>
struct fmt::formatter<ua::Decimal> : fmt::formatter<std::string>
{
  /// Writes the textual form of @p value to the format context.
  /// @param value The value to render.
  /// @param ctx   The {fmt} format context that receives the output.
  /// @return An iterator past the end of the written output.
  auto format(const ua::Decimal& value, fmt::format_context& ctx) const
  {
    return fmt::formatter<std::string>::format(ua::to_string(value), ctx);
  }
};

/// @endcond

#endif  // !UA_FMT_H
