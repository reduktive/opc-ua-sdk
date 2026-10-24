// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Abstract base for OPC UA structured (ExtensionObject) DataTypes.
/// @ingroup core_types

#ifndef UA_STRUCTURE_H
#define UA_STRUCTURE_H

#include "ua_includes.h"
#include "ua_resource_budgets.h"
#include "ua_built_in_type_id.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_locale_id.h"
#include <string>

#include "ua_codec_namespace_context.h"

namespace ua
{

class AddressSpace;
class Encoder;
class Decoder;
class NodeId;
class ExpandedNodeId;

/// Abstract base for every OPC UA structured DataType carried as an ExtensionObject.
///
/// Models the spec-defined structured-type hierarchy: generated DataTypes (and @ref Union) derive
/// from this base and implement its pure-virtual interfaces, while concrete instances are passed
/// polymorphically through @ref Variant and the codecs. The base supplies value equality and the
/// identity/serialization/cloning contract; derived types add their typed fields. Holds value
/// semantics - clients copy or @ref clone instances rather than sharing them.
///
/// @ingroup core_types
class Structure
{
public:
  /// Virtual destructor enabling polymorphic ownership through `unique_ptr<Structure>`.
  virtual ~Structure() = default;

  /// Compares two structures for member-wise value equality.
  ///
  /// Defaulted; two structures are equal when their dynamic types and all fields compare equal.
  /// Comparing instances of different concrete types is well-defined and yields `false`.
  ///
  /// @param obj Structure to compare against.
  /// @return `true` if both structures share a dynamic type and all fields compare equal; `false`
  ///         otherwise.
  bool operator==(const Structure& obj) const = default;

  /// Tests whether this structure is of, or derives from, the given DataType.
  ///
  /// Walks the structured-type supertype chain so that a derived instance reports `true` for any
  /// of its base DataTypes. Each derived type checks its own DataType and then defers to its
  /// supertype's override; this base, where every chain ends, answers `true` for Structure (i=22)
  /// and BaseDataType (i=24). StructureType (i=98) is the Enumeration of structure kinds, not a
  /// supertype, and answers `false`.
  ///
  /// @param ns     Namespace context used to resolve @p dataTypeId against this type's identity.
  /// @param dataTypeId DataType node identifier to test against.
  /// @return `true` if this structure is an instance of @p dataTypeId or one of its subtypes.
  virtual bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const;

  /// Returns the DataType node identifier of this structure, resolved in the given namespace.
  ///
  /// @param ns Namespace context that maps the type's namespace URI to a runtime index.
  /// @return The @ref NodeId of this concrete DataType.
  /// @see type_id() const
  virtual NodeId type_id(const CodecNamespaceContext& ns) const = 0;

  /// Returns the DataType identifier of this structure as a namespace-URI-qualified value.
  ///
  /// Carries the namespace URI directly, so the identity is self-describing and requires no
  /// namespace context to interpret.
  ///
  /// @return The @ref ExpandedNodeId of this concrete DataType.
  /// @see type_id(const CodecNamespaceContext&) const
  virtual ExpandedNodeId type_id() const = 0;

  /// Returns the OPC UA type name of this concrete DataType.
  ///
  /// @return This DataType's OPC UA type name.
  virtual String type_name() const = 0;

  /// Encodes this structure's DataType identifier (its encoding NodeId) onto the stream.
  ///
  /// Writes only the identity prefix an ExtensionObject carries before its body; @ref encode
  /// writes the field payload. Separated so callers can frame the body length independently.
  ///
  /// @param limit   Work budget guarding against pathologically nested encodings; shared across
  ///                the encode walk and consumed as nodes and edges are processed.
  /// @param ns      Namespace context resolving the encoding NodeId's namespace URI to an index.
  /// @param encoder Sink the identifier bytes are written to.
  virtual void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const = 0;

  /// Encodes this structure's field payload onto the stream.
  ///
  /// @param limit   Work budget guarding against pathologically nested encodings; shared across
  ///                the encode walk and consumed as nested structures are visited.
  /// @param encoder Sink the field bytes are written to.
  /// @see decode
  virtual void encode(StackDepth limit, Encoder& encoder) const;

  /// Decodes this structure's field payload from the stream into this instance.
  ///
  /// Overwrites the current field values with the decoded ones.
  ///
  /// @param limit   Work budget guarding against pathologically nested decodings; shared across
  ///                the decode walk and consumed as nested structures are visited.
  /// @param decoder Source the field bytes are read from.
  /// @see encode
  virtual void decode(StackDepth limit, Decoder& decoder);

  /// Returns an owning, independent deep copy of this structure.
  ///
  /// The clone is a distinct instance with no shared mutable state; the caller owns the returned
  /// pointer. Used to copy a structure held only through the polymorphic base.
  ///
  /// @return A `unique_ptr` owning a copy of the concrete type.
  virtual unique_ptr<Structure> clone() const = 0;

  /// Collapses localized-text fields under a set of session locales, recursing into nested fields.
  ///
  /// The default is a no-op. Generated types whose transitive field set contains @ref LocalizedText
  /// override this to reduce each aggregate field to the best match among @p locales and to recurse
  /// into nested `Structure`-derived fields. Invoked at service-response construction and sampling
  /// fan-out rather than on every encode, so it is not on a hot path.
  ///
  /// @param locales Ordered, most-preferred-first list of session locales used to pick each text.
  virtual void resolve(span<const LocaleId> locales);

  /// Returns a human-readable, indented rendering of this structure for diagnostics and logging.
  ///
  /// The format is for human consumption only and is not stable or machine-parseable.
  ///
  /// @param indent Number of indentation levels to prefix; used when nesting one structure in
  ///               another. Defaults to top level (0).
  /// @return The rendered text.
  virtual std::string to_string(int indent = 0) const = 0;

  /// Returns the built-in type tag for structured values, @ref BuiltInTypeId::ExtensionObject.
  ///
  /// Identifies all `Structure`-derived values as ExtensionObjects on the wire, independent of the
  /// concrete DataType.
  ///
  /// @return @ref BuiltInTypeId::ExtensionObject.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Default-constructs the abstract base subobject; only derived types may construct.
  Structure() = default;
  /// Copy-constructs the base subobject; protected to prevent slicing of the abstract base while
  /// still allowing derived types' defaulted copy constructors to copy this subobject.
  Structure(const Structure&) = default;
  /// Move-constructs the base subobject; protected to prevent slicing of the abstract base.
  Structure(Structure&&) noexcept = default;
  /// Copy-assigns the base subobject; protected to prevent slicing of the abstract base.
  /// @return Reference to this base subobject.
  Structure& operator=(const Structure&) = default;
  /// Move-assigns the base subobject; protected to prevent slicing of the abstract base.
  /// @return Reference to this base subobject.
  Structure& operator=(Structure&&) noexcept = default;

  /// Appends this structure's fields to @p output as part of @ref to_string.
  ///
  /// Extension point for derived types: each override writes its own fields, one per line, at the
  /// given indentation, then defers to its base to append inherited fields. Not called directly by
  /// clients.
  ///
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation level to prefix each appended field line.
  virtual void append_fields(std::string& output, int indent = 0) const;
};

/// Returns the OPC UA type name `"ExtensionObject"` for `Structure`.
///
/// Explicit specialisation of the `get_typename` primary template; all structured DataTypes are
/// carried on the wire as ExtensionObjects, so the generic type name is the ExtensionObject name
/// rather than any concrete DataType name.
///
/// @return The type name `"ExtensionObject"`.
template<>
inline string_view get_typename<Structure>()
{
  return "ExtensionObject";
}

/// Returns whether two structures have the same type and identical binary encoding.
///
/// Two structures are equivalent when they share the same DataType and their UA Binary
/// encodings are byte-for-byte identical. The comparison works across the static and dynamic
/// type boundary, so a statically typed structure and a dynamically typed one that encode to
/// the same bytes compare equal. Neither operand is modified. Does not throw.
///
/// @param a First structure to compare.
/// @param b Second structure to compare.
/// @return @c true if @p a and @p b have the same type and identical binary encoding;
///         @c false otherwise.
bool equivalent(const Structure& a, const Structure& b);

}  // namespace ua

#endif  // !UA_STRUCTURE_H
