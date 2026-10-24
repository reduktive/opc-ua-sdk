// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Arbitrary-precision OPC UA Decimal value (scaled integer mantissa).
/// @ingroup core_types

#ifndef UA_DECIMAL_H
#define UA_DECIMAL_H

#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_byte_string.h"

namespace ua
{

/// An arbitrary-precision decimal number, as defined by OPC 10000-6.
///
/// A Decimal represents the rational value `mantissa * 10^(-scale)`. The
/// mantissa is a signed, arbitrary-length integer carried in @ref value() as a
/// little-endian two's-complement @ref ByteString; @ref scale() is the
/// base-10 exponent. For example, a mantissa of `12345` with a scale of `2`
/// denotes `123.45`. A default-constructed Decimal has scale `0` and an empty
/// mantissa, which denotes the value `0`.
/// @ingroup core_types
class Decimal
{
public:
  /// Constructs a Decimal with scale `0` and an empty mantissa (the value `0`).
  Decimal() = default;
  /// Copies the scale and mantissa of @p other.
  /// @param other Decimal whose scale and mantissa are copied.
  Decimal(const Decimal& other) = default;
  /// Moves @p other's mantissa, leaving it with the empty (value `0`) mantissa.
  /// @param other Decimal whose mantissa is moved from; left with the empty mantissa.
  Decimal(Decimal&& other) noexcept = default;
  /// Copy-assigns the scale and mantissa of @p other.
  /// @param other Decimal whose scale and mantissa are copied.
  /// @return Reference to this Decimal.
  Decimal& operator=(const Decimal& other) = default;
  /// Move-assigns @p other's mantissa, leaving it with the empty (value `0`) mantissa.
  /// @param other Decimal whose mantissa is moved from; left with the empty mantissa.
  /// @return Reference to this Decimal.
  Decimal& operator=(Decimal&& other) noexcept = default;
  /// Destroys the Decimal, releasing its mantissa.
  ~Decimal() = default;

  /// Compares two Decimals for exact representational equality.
  ///
  /// Equality is structural: both the @ref scale() and the raw mantissa bytes
  /// must match. Two Decimals that denote the same rational number with
  /// different scales (e.g. `1.0` and `1.00`) are **not** equal.
  /// @param obj Decimal to compare against.
  /// @return `true` when both the scale and the raw mantissa bytes match.
  bool operator==(const Decimal& obj) const = default;

  /// Returns the base-10 exponent applied to the mantissa.
  ///
  /// The represented value is `mantissa * 10^(-scale)`; a positive scale moves
  /// the decimal point left, a negative scale moves it right.
  ///
  /// @return The base-10 exponent applied to the mantissa.
  const int16_t& scale() const;

  /// Returns a mutable reference to the base-10 exponent.
  ///
  /// @return Mutable reference to the base-10 exponent.
  /// @see scale() const
  int16_t& scale();

  /// Returns the signed mantissa as a little-endian two's-complement byte string.
  ///
  /// An empty byte string denotes a mantissa of `0`.
  ///
  /// @return The mantissa as a little-endian two's-complement byte string.
  const ByteString& value() const;

  /// Returns a mutable reference to the mantissa byte string.
  ///
  /// @return Mutable reference to the mantissa byte string.
  /// @see value() const
  ByteString& value();

  /// Resets to scale `0` and an empty mantissa (the value `0`).
  void clear();

  /// Returns the OPC UA built-in type identifier for Decimal.
  ///
  /// @return @ref BuiltInTypeId for this type.
  static BuiltInTypeId built_in_type_id();

private:
  int16_t mScale{0};
  ByteString mValue;
};

/// Returns the OPC UA type name `"Decimal"` for `Decimal`.
///
/// Explicit specialisation of the `get_typename` primary template.
///
/// @return The literal `"Decimal"`.
template<>
inline string_view get_typename<Decimal>()
{
  return "Decimal";
}

}  // namespace ua

#endif  // !UA_DECIMAL_H
