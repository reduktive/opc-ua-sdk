// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DYNAMIC_TYPE_DESCRIPTOR_H
#define UA_DYNAMIC_TYPE_DESCRIPTOR_H

/// @file
/// @brief Immutable metadata describing a dynamically registered structure or union type.
/// @ingroup core_types

#include "ua_includes.h"
#include "ua_built_in_type_id.h"
#include "ua_expanded_node_id.h"
#include "ua_string.h"
#include "ua_structure_type.h"
#include "ua_structure_definition.h"
#include <functional>
#include <optional>
#include <unordered_map>
#include <vector>

namespace ua
{

/// Maps a namespace index to its URI, supplied by the caller at registration time.
///
/// Server-side this wraps `NamespaceArray::get_namespace_uri()`; client-side it wraps the
/// `Array<String>` read from `Server_NamespaceArray` (i=2255). The function is invoked
/// synchronously during descriptor construction and is not retained afterwards.
///
/// @see NamespaceIndexLookup
using NamespaceUriLookup = std::function<String(uint16_t namespaceIndex)>;

/// Maps a namespace URI to its local index; the inverse of `NamespaceUriLookup`.
///
/// Used by `make_resolver()` and `register_all_with()` to translate URI-keyed registry
/// entries back to local NodeIds. Returns `std::nullopt` when the URI is not present in the
/// local namespace table. Server-side this wraps `NamespaceArray::get_index()`; client-side it
/// wraps a linear search over the `Array<String>` from node 2255.
///
/// @see NamespaceUriLookup
using NamespaceIndexLookup = std::function<std::optional<uint16_t>(string_view namespaceUri)>;

/// Immutable, shared metadata describing a dynamically registered structure or union type.
///
/// Exactly one descriptor exists per registered dynamic type. All `DynamicStructure` and
/// `DynamicUnion` instances of that type share a single descriptor through a
/// `shared_ptr<const DynamicStructureTypeDescriptor>`, so the object must be heap-allocated
/// (typically via `make_shared`) and is never copied or moved.
///
/// The descriptor stores @ref ExpandedNodeId values keyed by namespace URI rather than index,
/// making it portable across sessions; URI-to-index translation happens at encode/decode time
/// via `CodecNamespaceContext`.
///
/// The object is immutable after construction except for the two resolution hooks
/// (@ref set_field_built_in_type and @ref resolve_nested) that the owning
/// `DynamicTypeRegistry` uses to finalise the type graph.
///
/// @note Not copyable or movable: the field-name index holds `string_view`s into the stored
///       @ref StructureDefinition, which a move could invalidate.
/// @ingroup core_types
class DynamicStructureTypeDescriptor
{
public:
  /// Constructs a descriptor from a @ref StructureDefinition, resolving field DataTypes to URIs.
  ///
  /// @p nsLookup is invoked once per field during construction to populate
  /// @ref field_data_type_expanded. It is not retained - the descriptor is immutable afterwards.
  ///
  /// @param typeName    Human-readable type name (for example `"MyCustomType"`).
  /// @param typeId      DataType NodeId carrying its namespace URI.
  /// @param encodingId  Binary encoding NodeId carrying its namespace URI.
  /// @param definition  Field set and structure kind for the type.
  /// @param nsLookup    Resolves each field's namespace index to a URI.
  DynamicStructureTypeDescriptor(String typeName, ExpandedNodeId typeId, ExpandedNodeId encodingId,
    StructureDefinition definition, NamespaceUriLookup nsLookup);

  /// Constructs a descriptor for NS0-only types, where no namespace translation is required.
  /// @param typeName   Human-readable type name (for example `"MyCustomType"`).
  /// @param typeId     DataType NodeId carrying its namespace URI.
  /// @param encodingId Binary encoding NodeId carrying its namespace URI.
  /// @param definition Field set and structure kind for the type.
  DynamicStructureTypeDescriptor(
    String typeName, ExpandedNodeId typeId, ExpandedNodeId encodingId, StructureDefinition definition);

  /// Deleted copy constructor; descriptors are shared by `shared_ptr`, never copied.
  DynamicStructureTypeDescriptor(const DynamicStructureTypeDescriptor&) = delete;
  /// Deleted copy assignment; descriptors are shared by `shared_ptr`, never copied.
  DynamicStructureTypeDescriptor& operator=(const DynamicStructureTypeDescriptor&) = delete;
  /// Deleted move constructor; moving would invalidate the internal `string_view` field index.
  DynamicStructureTypeDescriptor(DynamicStructureTypeDescriptor&&) = delete;
  /// Deleted move assignment; moving would invalidate the internal `string_view` field index.
  DynamicStructureTypeDescriptor& operator=(DynamicStructureTypeDescriptor&&) = delete;

  /// Defaulted destructor (members are self-owning; copy/move already deleted above).
  ~DynamicStructureTypeDescriptor() = default;

  /// Returns the human-readable type name.
  /// @return The human-readable type name.
  const String& type_name() const;

  /// Returns the DataType NodeId, with its namespace expressed as a URI.
  /// @return The DataType NodeId, with its namespace expressed as a URI.
  const ExpandedNodeId& type_id() const;

  /// Returns the binary encoding NodeId, with its namespace expressed as a URI.
  /// @return The binary encoding NodeId, with its namespace expressed as a URI.
  const ExpandedNodeId& encoding_id() const;

  /// Returns whether the type is a plain structure, a union, or an optional-field structure.
  /// @return The `StructureType:` plain structure, union, or optional-field structure.
  StructureType structure_type() const;

  /// Returns the number of fields in the type.
  /// @return The number of fields in the type.
  size_t field_count() const;

  /// Returns the field metadata at @p index.
  ///
  /// @param index Zero-based field position; must be less than @ref field_count.
  /// @return The @ref StructureField metadata at @p index.
  const StructureField& field(size_t index) const;

  /// Returns the index of the field named @p name, or `std::nullopt` if no such field exists.
  /// @param name Field name to look up.
  /// @return The zero-based index of the field named @p name, or `std::nullopt` if no such field exists.
  std::optional<size_t> field_index(string_view name) const;

  /// Returns the built-in type the field at @p index encodes as.
  ///
  /// Precomputed from the field's DataType at construction, then possibly corrected via
  /// @ref set_field_built_in_type.
  ///
  /// @param index Zero-based field position; must be less than @ref field_count.
  /// @return The @ref BuiltInTypeId the field at @p index encodes as.
  BuiltInTypeId field_built_in_type(size_t index) const;

  /// Overrides the precomputed built-in type for the field at @p index.
  ///
  /// Used by `DynamicTypeRegistry` to correct the mapping for fields whose DataType is a non-NS0
  /// enum (which encodes as `Int32`) or a `UInteger`-based option set (which encodes as `UInt32`
  /// or `UInt64`).
  ///
  /// @param index       Zero-based field position; must be less than @ref field_count.
  /// @param builtInType Corrected built-in type for the field.
  /// @see field_built_in_type
  void set_field_built_in_type(size_t index, BuiltInTypeId builtInType);

  /// Returns the field's DataType as a URI-based, namespace-index-independent @ref ExpandedNodeId.
  ///
  /// Computed at construction from the field's DataType NodeId and the supplied
  /// @ref NamespaceUriLookup.
  ///
  /// @param index Zero-based field position; must be less than @ref field_count.
  /// @return The field's DataType as a URI-based, namespace-index-independent @ref ExpandedNodeId.
  const ExpandedNodeId& field_data_type_expanded(size_t index) const;

  /// Returns the descriptor resolved for the nested structure at @p fieldIndex, or `nullptr` if
  /// the field is not a structure or has not yet been resolved.
  ///
  /// @param fieldIndex Zero-based field position; must be less than @ref field_count.
  /// @see resolve_nested, fully_resolved
  /// @return The resolved descriptor for the nested structure at @p fieldIndex, or `nullptr` if the field is
  /// not a structure or has not yet been resolved.
  shared_ptr<const DynamicStructureTypeDescriptor> nested_descriptor(size_t fieldIndex) const;

  /// Resolves the nested descriptor for the structure field at @p fieldIndex.
  ///
  /// Called by `DynamicTypeRegistry` while wiring up the type graph; one of the two mutating
  /// hooks on an otherwise immutable descriptor.
  ///
  /// @param fieldIndex Zero-based field position; must be less than @ref field_count.
  /// @param descriptor Shared descriptor for the field's structure type.
  /// @see nested_descriptor, fully_resolved
  void resolve_nested(size_t fieldIndex, shared_ptr<const DynamicStructureTypeDescriptor> descriptor);

  /// Returns whether every nested structure field has had its descriptor resolved.
  ///
  /// @see resolve_nested
  /// @return `true` if every nested structure field has had its descriptor resolved; `false` otherwise.
  bool fully_resolved() const;

  /// Returns the underlying @ref StructureDefinition.
  /// @return The underlying @ref StructureDefinition.
  const StructureDefinition& definition() const;

  /// Maps a DataType NodeId to the @ref BuiltInTypeId it encodes as.
  ///
  /// NS0 numeric NodeIds use the standard OPC UA mapping (1 = Boolean, ... , 25 = DiagnosticInfo);
  /// unknown or custom NodeIds map to `ExtensionObject`, since the type is a structure.
  ///
  /// @param dataType DataType NodeId to classify.
  /// @return The corresponding built-in type.
  static BuiltInTypeId data_type_to_built_in_type(const NodeId& dataType);

private:
  String mTypeName;
  ExpandedNodeId mTypeId;
  ExpandedNodeId mEncodingId;
  StructureDefinition mDefinition;
  std::unordered_map<string_view, size_t> mFieldNameIndex;
  std::vector<BuiltInTypeId> mFieldBuiltInTypes;
  std::vector<ExpandedNodeId> mFieldDataTypeExpanded;
  std::vector<shared_ptr<const DynamicStructureTypeDescriptor>> mNestedDescriptors;
};

}  // namespace ua

#endif  // !UA_DYNAMIC_TYPE_DESCRIPTOR_H
