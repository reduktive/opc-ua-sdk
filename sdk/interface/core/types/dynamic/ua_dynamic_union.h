// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Runtime-shaped @ref ua::Union backed by a DynamicStructureTypeDescriptor.
/// @ingroup core_types

#ifndef UA_DYNAMIC_UNION_H
#define UA_DYNAMIC_UNION_H

#include "ua_includes.h"
#include "ua_union.h"
#include "ua_variant.h"
#include "ua_dynamic_type_descriptor.h"
#include <vector>

namespace ua
{

/// A @ref Union whose shape is defined at runtime by a @ref DynamicStructureTypeDescriptor.
///
/// Used for union DataTypes discovered at runtime (for example imported from a server's type
/// dictionary) that have no generated C++ class. The descriptor names the fields and their data
/// types; this instance carries the field values and the active switch selection. Every field slot
/// is eagerly default-constructed, so selecting a field overwrites a pre-existing value rather than
/// constructing one. The switch field is 1-based and identifies the active field; 0 is the null
/// union (no field selected).
///
/// Holds value semantics like every @ref Structure - instances are copied or @ref clone "cloned"
/// rather than shared. The descriptor is shared immutably (`shared_ptr<const ...>`) across all
/// instances of the same type and must outlive the union; copying a union copies the field values
/// and shares the same descriptor.
///
/// @ingroup core_types
class DynamicUnion : public Union
{
public:
  /// Constructs a null union of the type described by @p descriptor.
  ///
  /// All field slots are default-constructed and the switch field is 0; call @ref select to choose
  /// and populate the active field.
  ///
  /// @param descriptor Shared, immutable type description; its StructureType must be
  ///                   StructureType::Union or StructureType::UnionWithSubtypedValues. Must be
  ///                   non-null and must outlive this union.
  explicit DynamicUnion(shared_ptr<const DynamicStructureTypeDescriptor> descriptor);

  /// Copy-constructs a union, copying the field values and sharing @p other's descriptor.
  ///
  /// @param other Union whose field values are copied and whose descriptor is shared.
  DynamicUnion(const DynamicUnion& other);

  /// Move-constructs from @p other, leaving it in a valid but unspecified state.
  ///
  /// @param other Union whose field values and descriptor are moved from.
  DynamicUnion(DynamicUnion&& other) noexcept = default;

  /// Copy-assigns a union, replacing the field values and adopting @p other's descriptor.
  ///
  /// @param other Union whose field values are copied and whose descriptor is adopted.
  /// @return Reference to this union.
  DynamicUnion& operator=(const DynamicUnion& other);

  /// Move-assigns from @p other, leaving it in a valid but unspecified state.
  ///
  /// @param other Union whose field values and descriptor are moved from.
  /// @return Reference to this union.
  DynamicUnion& operator=(DynamicUnion&& other) noexcept = default;

  /// Defaulted destructor; completes the rule of five and keeps the type copyable/movable.
  ~DynamicUnion() override = default;

  /// Compares two dynamic unions for value equality.
  ///
  /// Equal when they describe the same type, select the same switch field, and their active field
  /// values compare equal. Two null unions of the same type are equal.
  ///
  /// @param other Union to compare against.
  /// @return `true` if the two unions are value-equal, `false` otherwise.
  bool operator==(const DynamicUnion& other) const;

  // --- Union interface ---

  /// Returns the 1-based index of the active field, or 0 if the union is null.
  ///
  /// @return The 1-based index of the active field, or 0 when the union is null.
  uint32_t switch_field() const override;
  /// Returns the number of fields defined by this union's descriptor.
  ///
  /// @return The number of fields defined by the descriptor.
  uint32_t field_count() const override;
  /// Resets the union to the null state, clearing the active field selection.
  ///
  /// @post `switch_field() == 0`.
  void clear() override;

  // --- Structure interface ---

  /// Tests whether this union is of, or derives from, the given DataType.
  ///
  /// @param ns     Namespace context used to resolve @p dataTypeId against this type's identity.
  /// @param dataTypeId DataType node identifier to test against.
  /// @return `true` if this union is an instance of @p dataTypeId or one of its subtypes.
  bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const override;
  /// Returns the DataType node identifier of this union, resolved in @p ns.
  ///
  /// @param ns Namespace context used to resolve this union's DataType identity.
  /// @return The DataType NodeId of this union, resolved in @p ns.
  /// @see type_id() const
  NodeId type_id(const CodecNamespaceContext& ns) const override;
  /// Returns the DataType identifier of this union as a namespace-URI-qualified value.
  ///
  /// @return The DataType identifier as a namespace-URI-qualified @ref ExpandedNodeId.
  /// @see type_id(const CodecNamespaceContext&) const
  ExpandedNodeId type_id() const override;
  /// Returns the OPC UA type name of this union's DataType.
  ///
  /// @return The OPC UA type name of this union's DataType.
  String type_name() const override;
  /// Encodes this union's encoding NodeId onto @p encoder.
  ///
  /// @param limit   Work budget guarding against pathologically nested encodings.
  /// @param ns      Namespace context resolving the encoding NodeId's namespace URI to an index.
  /// @param encoder Sink the identifier bytes are written to.
  void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const override;
  /// Encodes the switch field followed by the active field's value onto @p encoder.
  ///
  /// @param limit   Work budget guarding against pathologically nested encodings.
  /// @param encoder Sink the field bytes are written to.
  /// @see decode
  void encode(StackDepth limit, Encoder& encoder) const override;
  /// Decodes the switch field and active field value from @p decoder into this instance.
  ///
  /// Overwrites the current selection and field values with the decoded ones.
  ///
  /// @param limit   Work budget guarding against pathologically nested decodings.
  /// @param decoder Source the field bytes are read from.
  /// @see encode
  void decode(StackDepth limit, Decoder& decoder) override;
  /// Returns an owning, independent deep copy of this union.
  ///
  /// @return A `unique_ptr` owning a copy with the same descriptor and field values.
  unique_ptr<Structure> clone() const override;
  /// Returns a human-readable, indented rendering of this union for diagnostics and logging.
  ///
  /// The format is for human consumption only and is not stable or machine-parseable.
  ///
  /// @param indent Number of indentation levels to prefix; used when nesting one structure in
  ///               another. Defaults to top level (0).
  /// @return The rendered text.
  std::string to_string(int indent = 0) const override;

  // --- Field access ---

  /// Returns the value of the active field.
  ///
  /// @return Reference to the active field's value, valid until the union is modified or destroyed.
  /// @throws UaException if the union is null (no field selected).
  /// @see select, active_field_name
  const Variant& value() const;

  /// Selects the field named @p name and sets its value, updating the switch field accordingly.
  ///
  /// @param name       Field name as declared by the descriptor.
  /// @param fieldValue Value to store in the selected field; moved in.
  /// @throws UaException if @p name does not name a field of this union's type.
  /// @post `active_field_name() == name` and `value()` returns @p fieldValue.
  void select(string_view name, Variant fieldValue);

  /// Selects the field at zero-based @p index and sets its value, setting the switch field to
  /// `index + 1`.
  ///
  /// @param index      Zero-based field index in definition order, in `[0, field_count())`.
  /// @param fieldValue Value to store in the selected field; moved in.
  /// @throws UaException if @p index is out of range.
  /// @post `switch_field() == index + 1` and `value()` returns @p fieldValue.
  void select(size_t index, Variant fieldValue);

  /// Returns the name of the active field, or an empty view if the union is null.
  ///
  /// @return The active field's name, backed by the descriptor and valid for its lifetime; empty
  ///         when `switch_field() == 0`.
  string_view active_field_name() const;

  // --- Introspection ---

  /// Returns the type descriptor defining this union's fields and identity.
  ///
  /// @return Reference to the shared, immutable descriptor; valid for this union's lifetime.
  const DynamicStructureTypeDescriptor& descriptor() const;

private:
  shared_ptr<const DynamicStructureTypeDescriptor> mDescriptor;
  std::vector<Variant> mFields;
  uint32_t mSwitchField{0};

  size_t require_field_index(string_view name) const;
};

}  // namespace ua

#endif  // !UA_DYNAMIC_UNION_H
