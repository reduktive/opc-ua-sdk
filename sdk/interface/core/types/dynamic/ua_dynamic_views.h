// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Read-only and mutable views that interpret an integer as a named enumeration or bitmask.
/// @ingroup core_types

#ifndef UA_DYNAMIC_VIEWS_H
#define UA_DYNAMIC_VIEWS_H

#include "ua_includes.h"
#include <string>

namespace ua
{

class DynamicEnumTypeDescriptor;

/// Lightweight read-only view that interprets an integer as a named enumeration value.
///
/// Not a data type and not involved in encoding; this is a presentation helper that pairs a
/// raw integer value with a @ref DynamicEnumTypeDescriptor to provide name lookup and
/// formatting. The view does not own the descriptor: it holds a reference to it, so the
/// descriptor must outlive the view.
/// @ingroup core_types
class DynamicEnumView
{
public:
  /// Constructs a view pairing a raw integer value with its enum type descriptor.
  ///
  /// @param[in] value      Raw integer enum value to interpret.
  /// @param[in] descriptor Enum type descriptor used for name lookup; must outlive this view.
  DynamicEnumView(int64_t value, const DynamicEnumTypeDescriptor& descriptor);

  /// Returns the raw integer value.
  ///
  /// @return The raw integer value being interpreted.
  int64_t value() const;

  /// Returns the name for this value.
  ///
  /// @return The enumerator name, or an empty @c string_view if the value is not present in
  ///         the descriptor's definition.
  string_view value_name() const;

  /// Formats the value as a human-readable string.
  ///
  /// @return `"TypeName::ValueName"` for a known value, or `"TypeName(42)"` when the value is
  ///         not present in the descriptor's definition.
  std::string to_string() const;

  /// Returns the associated enum type descriptor.
  ///
  /// @return Reference to the descriptor used for name lookup; valid for this view's lifetime.
  const DynamicEnumTypeDescriptor& descriptor() const;

private:
  int64_t mValue;
  const DynamicEnumTypeDescriptor& mDescriptor;
};

/// Lightweight mutable view that interprets an integer as a named bitmask.
///
/// Each bit has a name defined by the @ref DynamicEnumTypeDescriptor's EnumDefinition, where
/// `EnumField::value()` is the bit number (0-based). This is a presentation and mutation helper,
/// not a data type, and it is not involved in encoding. Mutations are applied to an internal copy
/// of the raw value; call @ref underlying to retrieve the modified bitmask. The view does not own
/// the descriptor: it holds a reference to it, so the descriptor must outlive the view.
/// @ingroup core_types
class DynamicOptionSetView
{
public:
  /// Constructs a view pairing a raw bitmask value with its option set type descriptor.
  ///
  /// @param[in] value      Raw bitmask value to interpret.
  /// @param[in] descriptor Type descriptor used for bit-name lookup; must outlive this view.
  DynamicOptionSetView(uint64_t value, const DynamicEnumTypeDescriptor& descriptor);

  /// Tests whether the named bit is set.
  ///
  /// @param[in] bitName Name of the bit to test.
  /// @return `true` if the named bit is set, `false` otherwise.
  /// @throws UaException if @p bitName is not defined in the descriptor.
  bool is_set(string_view bitName) const;

  /// Sets or clears the named bit.
  ///
  /// @param[in] bitName Name of the bit to modify.
  /// @param[in] value   `true` to set the bit, `false` to clear it.
  /// @throws UaException if @p bitName is not defined in the descriptor.
  void set_bit(string_view bitName, bool value = true);

  /// Returns the current bitmask value, reflecting any mutations applied through this view.
  ///
  /// @return The current bitmask value, including any bits changed through this view.
  uint64_t underlying() const;

  /// Formats the set bits as a human-readable string.
  ///
  /// @return `"TypeName{Bit1, Bit3, Bit5}"`, listing the currently set bits by name.
  std::string to_string() const;

  /// Returns the associated enum type descriptor.
  ///
  /// @return Reference to the descriptor used for bit-name lookup; valid for this view's lifetime.
  const DynamicEnumTypeDescriptor& descriptor() const;

private:
  uint64_t mValue;
  const DynamicEnumTypeDescriptor& mDescriptor;

  int64_t require_bit_number(string_view bitName) const;
};

}  // namespace ua

#endif  // !UA_DYNAMIC_VIEWS_H
