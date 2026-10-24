// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Runtime-shaped @ref ua::Structure whose layout comes from a type descriptor.
/// @ingroup core_types

#ifndef UA_DYNAMIC_STRUCTURE_H
#define UA_DYNAMIC_STRUCTURE_H

#include "ua_includes.h"
#include "ua_structure.h"
#include "ua_variant.h"
#include "ua_dynamic_type_descriptor.h"
#include <vector>

namespace ua
{

/// A @ref Structure whose shape is defined at runtime by a @ref DynamicStructureTypeDescriptor.
///
/// Represents an instance of a structured DataType that is not known at compile time - for example
/// a custom server type discovered from a NodeSet or read over the wire - so its fields are carried
/// in a @ref Variant vector rather than as typed members. Handles plain structures, structures with
/// optional fields, and structures whose fields may carry subtypes. The overloaded
/// `StructureField::isOptional` flag controls presence only for
/// `StructureType::StructureWithOptionalFields`; for `StructureWithSubtypedValues` it permits a
/// subtype and never suppresses the field.
///
/// The instance shares an immutable descriptor with every other instance of the same type via
/// `shared_ptr<const DynamicStructureTypeDescriptor>`; the descriptor outlives and is unmodified by
/// the instance. All fields are eagerly default-constructed from their declared DataType at
/// construction. For optional fields the slot is populated but its encoding-mask bit is unset, so
/// the field is absent on the wire until marked present via @ref set_field_present. Holds value
/// semantics - copy or @ref clone instances rather than sharing them.
///
/// @ingroup core_types
class DynamicStructure : public Structure
{
public:
  /// Constructs an instance of the type described by @p descriptor with all fields default-valued.
  ///
  /// Every field is eagerly default-constructed from its declared DataType; optional fields start
  /// absent (encoding-mask bit unset).
  ///
  /// @param descriptor Shared, immutable type metadata; retained for the lifetime of the instance.
  ///                   Must not be null.
  explicit DynamicStructure(shared_ptr<const DynamicStructureTypeDescriptor> descriptor);

  /// Copy-constructs an independent instance sharing the same descriptor.
  /// @param other Structure to copy from.
  DynamicStructure(const DynamicStructure& other);
  /// Move-constructs from @p other, leaving it in a valid but unspecified state.
  /// @param other Structure to move from.
  DynamicStructure(DynamicStructure&& other) noexcept = default;
  /// Copy-assigns from @p other, replacing this instance's fields and descriptor.
  /// @param other Structure to copy from.
  /// @return Reference to this structure.
  DynamicStructure& operator=(const DynamicStructure& other);
  /// Move-assigns from @p other, leaving it in a valid but unspecified state.
  /// @param other Structure to move from.
  /// @return Reference to this structure.
  DynamicStructure& operator=(DynamicStructure&& other) noexcept = default;

  /// Defaulted destructor; completes the rule of five and keeps the type copyable/movable.
  ~DynamicStructure() override = default;

  /// Compares two dynamic structures for value equality.
  ///
  /// Equal when both refer to the same DataType and all corresponding fields - including the
  /// presence of optional fields - compare equal.
  /// @param other Structure to compare against.
  /// @return `true` if both refer to the same DataType and all corresponding fields, including the presence
  /// of optional fields, compare equal; `false` otherwise.
  bool operator==(const DynamicStructure& other) const;

  // --- Structure interface ---

  /// Tests whether this structure is of, or derives from, the given DataType.
  ///
  /// @param ns     Namespace context used to resolve @p dataTypeId against this type's identity.
  /// @param dataTypeId DataType node identifier to test against.
  /// @return `true` if this structure is an instance of @p dataTypeId or one of its subtypes.
  bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const override;

  /// Returns this structure's DataType node identifier, resolved in the given namespace.
  ///
  /// @param ns Namespace context that maps the descriptor's namespace URI to a runtime index.
  /// @return The @ref NodeId of this DataType.
  /// @see type_id() const
  NodeId type_id(const CodecNamespaceContext& ns) const override;

  /// Returns this structure's DataType identifier as a namespace-URI-qualified value.
  ///
  /// Taken directly from the descriptor, so the identity is self-describing and needs no namespace
  /// context to interpret.
  ///
  /// @return The @ref ExpandedNodeId of this DataType.
  /// @see type_id(const CodecNamespaceContext&) const
  ExpandedNodeId type_id() const override;

  /// Returns this type's human-readable name, as recorded in the descriptor.
  /// @return This type's human-readable name, as recorded in the descriptor.
  String type_name() const override;

  /// Encodes this structure's encoding NodeId (its ExtensionObject identity prefix) onto the stream.
  ///
  /// @param limit   Work budget guarding against pathologically nested encodings; consumed as the
  ///                encode walk proceeds.
  /// @param ns      Namespace context resolving the encoding NodeId's namespace URI to an index.
  /// @param encoder Sink the identifier bytes are written to.
  void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const override;

  /// Encodes the field payload onto the stream in descriptor field order.
  ///
  /// For a structure with optional fields, writes the encoding mask first, then only the fields
  /// marked present.
  ///
  /// @param limit   Work budget guarding against pathologically nested encodings; consumed as nested
  ///                structures are visited.
  /// @param encoder Sink the field bytes are written to.
  /// @see decode
  void encode(StackDepth limit, Encoder& encoder) const override;

  /// Decodes the field payload from the stream, overwriting this instance's fields.
  ///
  /// For a structure with optional fields, reads the encoding mask first and decodes only the
  /// fields it marks present, leaving absent fields default-valued.
  ///
  /// @param limit   Work budget guarding against pathologically nested decodings; consumed as nested
  ///                structures are visited.
  /// @param decoder Source the field bytes are read from.
  /// @see encode
  void decode(StackDepth limit, Decoder& decoder) override;

  /// Returns an owning, independent deep copy of this structure.
  ///
  /// The clone shares the same descriptor but copies all field values; the caller owns the returned
  /// pointer.
  ///
  /// @return A `unique_ptr` owning the copy.
  unique_ptr<Structure> clone() const override;

  /// Returns a human-readable, indented rendering of this structure for diagnostics and logging.
  ///
  /// The format is for human consumption only and is not stable or machine-parseable.
  ///
  /// @param indent Number of indentation levels to prefix; used when nesting one structure in
  ///               another. Defaults to top level (0).
  /// @return The rendered text.
  std::string to_string(int indent = 0) const override;

  // --- Field access by name ---

  /// Returns a mutable reference to the field named @p name.
  ///
  /// For an optional field this returns its slot but does not mark it present; use
  /// @ref set_field_present to include it on the wire.
  ///
  /// @param name Field name, as declared in the type definition.
  /// @return Reference to the field's value, valid until the structure is modified or destroyed.
  /// @throws UaException if no field has that name.
  Variant& operator[](string_view name);

  /// Returns a read-only reference to the field named @p name.
  ///
  /// @param name Field name, as declared in the type definition.
  /// @return Reference to the field's value, valid until the structure is modified or destroyed.
  /// @throws UaException if no field has that name.
  const Variant& operator[](string_view name) const;

  // --- Field access by index (zero-based, definition order) ---

  /// Returns a mutable reference to the field at @p index in definition order.
  ///
  /// @param index Zero-based field index, less than @ref field_count.
  /// @return Reference to the field's value, valid until the structure is modified or destroyed.
  /// @throws UaException if @p index is out of range.
  Variant& field(size_t index);

  /// Returns a read-only reference to the field at @p index in definition order.
  ///
  /// @param index Zero-based field index, less than @ref field_count.
  /// @return Reference to the field's value, valid until the structure is modified or destroyed.
  /// @throws UaException if @p index is out of range.
  const Variant& field(size_t index) const;

  // --- Optional field support (StructureWithOptionalFields only) ---

  /// Reports whether the field named @p name is currently present.
  ///
  /// A mandatory field is always present. An optional field in a
  /// `StructureWithOptionalFields` is present only after @ref set_field_present marks it so. A field
  /// whose `isOptional` flag means "allows subtyping" is mandatory and therefore always present. An
  /// unknown field name yields `false` rather than throwing.
  ///
  /// @param name Field name, as declared in the type definition.
  /// @return `true` if the field exists and is present (will be encoded); `false` otherwise.
  bool has_field(string_view name) const;

  /// Sets whether the optional field named @p name is present (encoded on the wire).
  ///
  /// Toggles the field's encoding-mask bit; the field's slot value is retained either way, so
  /// clearing and re-setting presence does not discard the value.
  ///
  /// @param name    Field name, as declared in the type definition.
  /// @param present `true` to include the field on the wire, `false` to omit it.
  /// @throws UaException if no field has that name, or if the named field is not an optional field
  ///         of a `StructureWithOptionalFields` definition.
  /// @see has_field
  void set_field_present(string_view name, bool present);

  // --- Introspection ---

  /// Returns the shared, immutable descriptor defining this structure's type and field layout.
  /// @return The shared, immutable @ref DynamicStructureTypeDescriptor defining this structure's type and
  /// field layout.
  const DynamicStructureTypeDescriptor& descriptor() const;

  /// Returns the number of fields declared by the type, including optional ones.
  /// @return The number of fields declared by the type, including optional ones.
  size_t field_count() const;

private:
  shared_ptr<const DynamicStructureTypeDescriptor> mDescriptor;
  std::vector<Variant> mFields;
  uint32_t mEncodingMask{0};

  size_t require_field_index(string_view name) const;
};

}  // namespace ua

#endif  // !UA_DYNAMIC_STRUCTURE_H
