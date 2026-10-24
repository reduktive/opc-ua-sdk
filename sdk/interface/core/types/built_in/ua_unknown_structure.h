// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Structure placeholder that preserves the raw body of an unresolved ExtensionObject.
/// @ingroup core_types

#ifndef UA_UNKNOWN_STRUCTURE_H
#define UA_UNKNOWN_STRUCTURE_H

#include "ua_includes.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_result.h"
#include "ua_structure.h"
#include "ua_structure_factory.h"
#include "ua_expanded_node_id.h"
#include "ua_byte_string.h"

namespace ua
{

class Variant;

/// A @ref Structure of an unresolved type whose raw encoded body is preserved verbatim.
///
/// Produced when the decoder cannot resolve an ExtensionObject's encoding id to a concrete
/// type. Rather than discard the value, the raw encoded body is kept unchanged (tagged with
/// the codec it came from) so it can be re-emitted losslessly on the wire, or reified into a
/// concrete type later once the type model becomes known.
///
/// Identity contract: an unknown structure holds ONLY the wire `TypeId` - i.e. the *encoding
/// id* (the DefaultBinary/DefaultXml encoding node), which is codec-specific. The *DataType id*
/// is genuinely unknowable without the type model, so @ref type_id is unsupported and
/// @ref is_of_type always returns `false`. Only @ref encode_id (writes the encoding id) and
/// @ref encode (writes the preserved body) participate in round-trip.
///
/// @note Not thread-safe: a single instance must not be accessed concurrently from multiple
///       threads without external synchronisation.
/// @ingroup core_types
class UnknownStructure : public Structure
{
public:
  /// Codec that produced the preserved body.
  ///
  /// The encoding id and body are a matched pair: re-emit verbatim to the same codec. An XML
  /// body may also ride a binary ExtensionObject via encoding byte 2; a binary body cannot be
  /// re-emitted as XML, since that would require the other codec's encoding id.
  enum class BodyEncoding
  {
    Binary,  ///< Body is OPC UA Binary encoded.
    Xml  ///< Body is OPC UA XML encoded.
  };

  /// Constructs the empty-body form, holding only the encoding id.
  ///
  /// Models a null/empty ExtensionObject, or an as-yet-uncaptured placeholder.
  ///
  /// @param encodingId The unresolved wire `TypeId` (encoding id). Copied.
  explicit UnknownStructure(const NodeId& encodingId);

  /// Constructs the body-preserving form, retaining the raw encoded body.
  ///
  /// @param encodingId   The unresolved wire `TypeId` (encoding id). Moved in.
  /// @param bodyEncoding Codec the @p body content is encoded in.
  /// @param body         Raw encoded body content in @p bodyEncoding form. Moved in.
  UnknownStructure(NodeId encodingId, BodyEncoding bodyEncoding, ByteString body);

  /// Reports whether this structure matches a DataType id; always `false`.
  ///
  /// The DataType id is unknown for an unknown structure, so no positive type match is
  /// possible.
  ///
  /// @param ns     Namespace context; ignored, since no DataType id is known to resolve against.
  /// @param dataTypeId DataType node identifier to test against; ignored.
  /// @return `false` unconditionally.
  bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const override;

  /// Unsupported: the DataType id of an unknown structure cannot be determined.
  ///
  /// Only the encoding id is known, not the DataType id, so this operation has no meaningful
  /// result.
  ///
  /// @param ns Namespace context; ignored, as no DataType id is available to resolve.
  /// @return Never returns normally; always throws @ref UaException with `Status::BadNotSupported`.
  NodeId type_id(const CodecNamespaceContext& ns) const override;

  /// Unsupported: the DataType id of an unknown structure cannot be determined.
  ///
  /// Only the encoding id is known, not the DataType id, so this operation has no meaningful
  /// result.
  ///
  /// @return Never returns normally; always throws @ref UaException with `Status::BadNotSupported`.
  ExpandedNodeId type_id() const override;

  /// Returns a human-readable name for the structure type.
  ///
  /// @return The placeholder type name `"Unknown"`.
  String type_name() const override;

  /// Encodes the encoding id (wire `TypeId`) to @p encoder.
  ///
  /// @param limit   Remaining stack depth budget guarding against unbounded nesting.
  /// @param ns      Namespace context mapping namespace indices for the target codec.
  /// @param encoder Sink that receives the encoded encoding id.
  void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const override;

  /// Encodes the preserved raw body to @p encoder verbatim.
  ///
  /// Re-emits the captured body unchanged; correct round-trip requires @p encoder use the same
  /// codec as @ref body_encoding (see @ref BodyEncoding for the binary/XML interplay).
  ///
  /// @param limit   Remaining stack depth budget guarding against unbounded nesting.
  /// @param encoder Sink that receives the preserved body.
  void encode(StackDepth limit, Encoder& encoder) const override;

  /// Decodes a structure body from @p decoder into this instance.
  ///
  /// @param limit   Remaining stack depth budget guarding against unbounded nesting.
  /// @param decoder Source of the encoded body.
  void decode(StackDepth limit, Decoder& decoder) override;

  /// Returns an owning deep copy of this structure.
  ///
  /// @return A new @ref Structure holding the same encoding id, encoding, and preserved body.
  unique_ptr<Structure> clone() const override;

  /// Returns a human-readable, indented rendering of the structure.
  ///
  /// @param indent Number of indentation levels to prefix nested lines with.
  /// @return The rendered text.
  std::string to_string(int indent = 0) const override;

  /// Returns the unresolved encoding id (wire `TypeId`).
  ///
  /// @return Reference to the held encoding id; valid for this instance's lifetime.
  const NodeId& encoding_id() const;

  /// Returns which codec the preserved body is encoded in.
  ///
  /// @return The body's @ref BodyEncoding (Binary or Xml).
  BodyEncoding body_encoding() const;

  /// Returns the preserved raw encoded body.
  ///
  /// @return Reference to the held body; empty for the empty-body form. Valid for this
  ///         instance's lifetime.
  const ByteString& encoded_data() const;

private:
  NodeId mEncodingId;
  BodyEncoding mBodyEncoding{BodyEncoding::Binary};
  ByteString mBody;
};

/// Reifies an opaque structured value once its type has become known.
///
/// An `UnknownStructure` preserves the raw encoded body of a type the decoder could not resolve.
/// When a `StructureResolver` can now resolve that body's encoding id (e.g. one obtained from
/// `DynamicTypeRegistry::make_resolver()` or `StructureFactory::resolver()`), this function
/// re-decodes the preserved body in its source codec to yield the concrete value - a generated
/// type, a `DynamicStructure`, or whatever else the resolver produces.
///
/// Reification is optional and lossless: if @p resolver still cannot resolve the encoding id, a
/// clone of the opaque value is returned unchanged with good status.
///
/// @param opaque   The unresolved structured value whose preserved body is re-decoded.
/// @param resolver Resolves the body's encoding id to a concrete type; may resolve nothing.
/// @param limits   Encoding limits applied during the re-decode (e.g. nesting/size bounds).
/// @param ns       Translates embedded namespace indexes during the re-decode. Must match the index
///                 space the preserved body is in: identity (the default) for wire/gateway bodies
///                 already in server indexes; the importer's file-local-to-server mapping for
///                 import-sourced bodies.
/// @return The reified concrete `Structure` on success (or an unchanged clone when unresolved),
///         or an `ErrorDetail` if re-decoding the preserved body fails. Never throws.
/// @see decode_unknowns_in_place
Result<unique_ptr<Structure>> decode_unknown(const UnknownStructure& opaque,
  const StructureResolver& resolver, const EncodingLimits& limits, const CodecNamespaceContext& ns = {});

/// Reifies every resolvable opaque structure contained in a Variant, in place.
///
/// Walks @p value and replaces each `UnknownStructure` the resolver can now resolve with its
/// reified concrete value, handling both a scalar structure and an array of structures. The
/// operation is idempotent and a no-op when @p resolver is empty or no contained value is
/// resolvable; unresolved entries are left untouched.
///
/// @param[in,out] value    Variant to reify in place; modified only where a contained structure is
///                         resolved.
/// @param resolver         Resolves contained encoding ids to concrete types; may resolve nothing.
/// @param limits           Encoding limits applied during each re-decode.
/// @param ns               Translates embedded namespace indexes during each re-decode; see
///                         `decode_unknown` for the index-space contract.
/// @see decode_unknown
void decode_unknowns_in_place(Variant& value, const StructureResolver& resolver, const EncodingLimits& limits,
  const CodecNamespaceContext& ns = {});

}  // namespace ua

#endif  // !UA_UNKNOWN_STRUCTURE_H
