// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Shared metadata descriptor for dynamic enumeration and option-set types.
/// @ingroup core_types

#ifndef UA_DYNAMIC_ENUM_TYPE_DESCRIPTOR_H
#define UA_DYNAMIC_ENUM_TYPE_DESCRIPTOR_H

#include "ua_includes.h"
#include "ua_expanded_node_id.h"
#include "ua_string.h"
#include "ua_enum_definition.h"
#include <optional>
#include <unordered_map>

namespace ua
{

/// Immutable, shared metadata describing a dynamic enumeration or UInteger-based option-set type.
///
/// Exactly one descriptor exists per registered dynamic enum/option-set type. All views and
/// `DynamicOptionSet` instances of that type share the single descriptor through a
/// `shared_ptr<const DynamicEnumTypeDescriptor>`, so the object is effectively `const` after
/// construction and safe to read concurrently from any thread.
///
/// For enumerations, each `EnumField::value()` is the integer enum value. For option sets, each
/// `EnumField::value()` is the 0-based bit number.
///
/// @note Non-copyable and non-movable: the internal name/value lookup maps hold `string_view`s into
///       the owned @ref EnumDefinition strings, which a move (or small-string optimisation) could
///       invalidate. Always heap-allocate via `make_shared`.
/// @ingroup core_types
class DynamicEnumTypeDescriptor
{
public:
  /// Constructs a descriptor from an enum definition and its type identity.
  ///
  /// Builds the forward (value to name) and reverse (name to value) lookup maps from
  /// @p definition. The descriptor takes ownership of @p definition; the lookup maps reference its
  /// strings, so it must outlive every returned `string_view`.
  ///
  /// @param typeName    Human-readable type name (e.g. `"MyPermissionFlags"`).
  /// @param typeId      DataType NodeId, including its namespace URI.
  /// @param isOptionSet `true` if this describes an option set (bitmask), `false` for a plain enum.
  /// @param definition  Enum definition supplying the fields; ownership is transferred.
  DynamicEnumTypeDescriptor(
    String typeName, ExpandedNodeId typeId, bool isOptionSet, EnumDefinition definition);

  /// Deleted: descriptors are shared by `shared_ptr`, never copied (see class @note).
  DynamicEnumTypeDescriptor(const DynamicEnumTypeDescriptor&) = delete;
  /// Deleted: descriptors are shared by `shared_ptr`, never copied (see class @note).
  DynamicEnumTypeDescriptor& operator=(const DynamicEnumTypeDescriptor&) = delete;
  /// Deleted: moving would invalidate the internal `string_view` lookup maps (see class @note).
  DynamicEnumTypeDescriptor(DynamicEnumTypeDescriptor&&) = delete;
  /// Deleted: moving would invalidate the internal `string_view` lookup maps (see class @note).
  DynamicEnumTypeDescriptor& operator=(DynamicEnumTypeDescriptor&&) = delete;

  /// Defaulted destructor; completes the rule of five without affecting copyability.
  ~DynamicEnumTypeDescriptor() = default;

  /// Returns the human-readable type name.
  /// @return The human-readable type name.
  const String& type_name() const;

  /// Returns the DataType NodeId, including its namespace URI.
  /// @return The DataType NodeId, including its namespace URI.
  const ExpandedNodeId& type_id() const;

  /// Returns `true` if this describes an option set (bitmask), `false` for a plain enumeration.
  /// @return `true` if this describes an option set (bitmask); `false` for a plain enumeration.
  bool is_option_set() const;

  /// Returns the field name for a given enum value.
  ///
  /// @param value Integer enum value, or 0-based bit number for an option set.
  /// @return The field name, or `nullopt` if no field has that value. The view references storage
  ///         owned by this descriptor and stays valid for its lifetime.
  /// @see value_for_name
  std::optional<string_view> name_for_value(int64_t value) const;

  /// Returns the enum value for a given field name.
  ///
  /// @param name Field name to look up.
  /// @return The integer value (or 0-based bit number for an option set), or `nullopt` if no field
  ///         has that name.
  /// @see name_for_value
  std::optional<int64_t> value_for_name(string_view name) const;

  /// Returns the underlying enum definition supplying the fields.
  /// @return The underlying @ref EnumDefinition supplying the fields.
  const EnumDefinition& definition() const;

private:
  String mTypeName;
  ExpandedNodeId mTypeId;
  bool mIsOptionSet;
  EnumDefinition mDefinition;
  std::unordered_map<int64_t, string_view> mValueToName;
  std::unordered_map<string_view, int64_t> mNameToValue;
};

}  // namespace ua

#endif  // !UA_DYNAMIC_ENUM_TYPE_DESCRIPTOR_H
