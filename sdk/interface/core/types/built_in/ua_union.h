// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Abstract base for OPC UA union structured types (at most one active field).
/// @ingroup core_types

#ifndef UA_UNION_H
#define UA_UNION_H

#include "ua_structure.h"

namespace ua
{

/// Abstract base for OPC UA union structured DataTypes.
///
/// A union is a @ref Structure that holds at most one of its defined fields at a time,
/// selected by a 1-based switch value; switch 0 is the null union (no field set).
/// Generated union DataTypes derive from this class and implement the field accessors
/// alongside the @ref Structure encoding/cloning contract.
///
/// @ingroup core_types
class Union : public Structure
{
public:
  /// Defaulted virtual destructor; destruction runs through the polymorphic @ref Structure base.
  virtual ~Union() = default;

  /// Returns the 1-based index of the active field, or 0 if no field is set.
  ///
  /// @return The selected field's 1-based index in `[1, field_count()]`, or 0 for the
  ///         null union (no field set).
  virtual uint32_t switch_field() const = 0;

  /// Returns the number of fields defined by this union type.
  ///
  /// @return The count of fields the union type declares.
  virtual uint32_t field_count() const = 0;

  /// Resets the union to the null state.
  ///
  /// @post `switch_field() == 0` and no field value is held.
  virtual void clear() = 0;

  /// Answers true for Union (i=12756), then as @ref Structure::is_of_type does. A derived union type
  /// checks its own type and then defers here, so every union is a Union, a Structure and a BaseDataType.
  ///
  /// @param ns         Namespace context; Union and its supertypes are namespace-0 ids.
  /// @param dataTypeId DataType node identifier to test against.
  /// @return `true` if @p dataTypeId is Union, Structure or BaseDataType.
  bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const override;

  /// Returns the OPC UA built-in type id for Union.
  ///
  /// @return The built-in type id identifying Union values.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Default-constructs the base subobject (null union); only derived types may construct.
  Union() = default;
  /// Copy-constructs the base subobject; protected to prevent slicing of the abstract base.
  Union(const Union&) = default;
  /// Move-constructs the base subobject; protected to prevent slicing of the abstract base.
  Union(Union&&) noexcept = default;
  /// Copy-assigns the base subobject; protected to prevent slicing of the abstract base.
  /// @return Reference to this base subobject.
  Union& operator=(const Union&) = default;
  /// Move-assigns the base subobject; protected to prevent slicing of the abstract base.
  /// @return Reference to this base subobject.
  Union& operator=(Union&&) noexcept = default;
};

/// Maps `Union` to the OPC UA type name "Union".
///
/// @return The type name `"Union"`.
template<>
inline string_view get_typename<Union>()
{
  return "Union";
}

}  // namespace ua

#endif  // !UA_UNION_H
