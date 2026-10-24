// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Structure-based OptionSet whose bit definitions are resolved at runtime.
/// @ingroup core_types

#ifndef UA_DYNAMIC_OPTION_SET_H
#define UA_DYNAMIC_OPTION_SET_H

#include "ua_includes.h"
#include "ua_option_set.h"

namespace ua
{

class DynamicEnumTypeDescriptor;

/// A Structure-based OptionSet whose bit definitions are known only at runtime.
///
/// Inherits from the generated @ref OptionSet, which supplies the `Value` and `ValidBits`
/// @ref ByteString fields plus encode/decode support. This type layers named bit access on top via
/// a shared @ref DynamicEnumTypeDescriptor whose every `EnumField::value()` is the bit number
/// (0-based) of the corresponding flag.
///
/// Use this for option sets that need more than 64 bits or that track valid bits. For
/// UInteger-based option sets (64 bits or fewer), use @ref DynamicOptionSetView instead.
/// @ingroup core_types
class DynamicOptionSet : public OptionSet
{
public:
  /// Constructs an empty option set bound to the given type descriptor.
  ///
  /// The `Value` and `ValidBits` ByteStrings start empty (all bits clear). The descriptor supplies
  /// the bit-name-to-bit-number mapping used by the named-bit accessors.
  ///
  /// @param descriptor Shared, immutable metadata for this option-set type; must describe an option
  ///                   set (`is_option_set() == true`) and outlives this instance via shared
  ///                   ownership. Must not be null.
  explicit DynamicOptionSet(shared_ptr<const DynamicEnumTypeDescriptor> descriptor);

  /// Copy-constructs, deep-copying the bit data; the descriptor binding is shared, not duplicated.
  /// @param other Option set to copy from.
  DynamicOptionSet(const DynamicOptionSet& other) = default;

  /// Move-constructs; the source is left in a valid but unspecified state.
  /// @param other Option set to move from.
  DynamicOptionSet(DynamicOptionSet&& other) noexcept = default;

  /// Copy-assigns, deep-copying the bit data; the descriptor binding is shared, not duplicated.
  /// @param other Option set to copy from.
  /// @return Reference to this option set.
  DynamicOptionSet& operator=(const DynamicOptionSet& other) = default;

  /// Move-assigns; the source is left in a valid but unspecified state.
  /// @param other Option set to move from.
  /// @return Reference to this option set.
  DynamicOptionSet& operator=(DynamicOptionSet&& other) noexcept = default;

  /// Defaulted destructor; completes the rule of five and keeps the type copyable/movable.
  ~DynamicOptionSet() override = default;

  /// Compares two option sets for value equality.
  ///
  /// Two instances are equal when they share the same type descriptor and their `Value` and
  /// `ValidBits` ByteStrings compare equal.
  /// @param other Option set to compare against.
  /// @return `true` if both share the same type descriptor and their `Value` and `ValidBits` ByteStrings
  /// compare equal; `false` otherwise.
  bool operator==(const DynamicOptionSet& other) const;

  // --- Structure interface ---

  /// Tests whether this option set is of, or derives from, the given DataType.
  ///
  /// @param ns     Namespace context used to resolve @p dataTypeId against this type's identity.
  /// @param dataTypeId DataType node identifier to test against.
  /// @return `true` if @p dataTypeId matches this type or one of its supertypes.
  /// @see Structure::is_of_type
  bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const override;

  /// Returns the DataType node identifier carried by the descriptor, resolved in @p ns.
  ///
  /// @param ns Namespace context that maps the type's namespace URI to a runtime index.
  /// @return The @ref NodeId of this option set's DataType.
  /// @see type_id() const
  NodeId type_id(const CodecNamespaceContext& ns) const override;

  /// Returns the DataType identifier carried by the descriptor as a namespace-URI-qualified value.
  ///
  /// @return The @ref ExpandedNodeId of this option set's DataType.
  /// @see type_id(const CodecNamespaceContext&) const
  ExpandedNodeId type_id() const override;

  /// Returns the type name carried by the descriptor.
  /// @return The type name carried by the descriptor.
  String type_name() const override;

  /// Encodes this option set's encoding NodeId onto the stream.
  ///
  /// @param limit   Work budget guarding against pathologically nested encodings.
  /// @param ns      Namespace context resolving the encoding NodeId's namespace URI to an index.
  /// @param encoder Sink the identifier bytes are written to.
  /// @see Structure::encode_id
  void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const override;

  /// Returns an owning, independent deep copy of this option set, including its descriptor binding.
  ///
  /// @return A `unique_ptr` owning a copy of this concrete type.
  unique_ptr<Structure> clone() const override;

  /// Returns a human-readable, indented rendering of this option set for diagnostics and logging.
  ///
  /// The format is for human consumption only and is not stable or machine-parseable.
  ///
  /// @param indent Number of indentation levels to prefix; defaults to top level (0).
  /// @return The rendered text.
  std::string to_string(int indent = 0) const override;

  // --- Named bit access on Value ---

  /// Tests whether the named bit is set in the `Value` ByteString.
  ///
  /// @param bitName Flag name as defined by the type descriptor.
  /// @return `true` if the named bit is set.
  /// @throws UaException `BadInvalidArgument` if @p bitName is unknown to the descriptor, or
  ///         `BadOutOfRange` if its bit number is negative.
  bool is_set(string_view bitName) const;

  /// Sets or clears the named bit in the `Value` ByteString.
  ///
  /// Grows the `Value` ByteString as needed to address the bit.
  ///
  /// @param bitName  Flag name as defined by the type descriptor.
  /// @param bitValue `true` to set the bit, `false` to clear it. Defaults to `true`.
  /// @throws UaException `BadInvalidArgument` if @p bitName is unknown to the descriptor, or
  ///         `BadOutOfRange` if its bit number is negative.
  void set_bit(string_view bitName, bool bitValue = true);

  // --- Named bit access on ValidBits ---

  /// Tests whether the named bit is marked as valid in the `ValidBits` ByteString.
  ///
  /// @param bitName Flag name as defined by the type descriptor.
  /// @return `true` if the named bit is marked valid.
  /// @throws UaException `BadInvalidArgument` if @p bitName is unknown to the descriptor, or
  ///         `BadOutOfRange` if its bit number is negative.
  bool is_valid(string_view bitName) const;

  /// Sets or clears the named bit in the `ValidBits` ByteString.
  ///
  /// Grows the `ValidBits` ByteString as needed to address the bit.
  ///
  /// @param bitName Flag name as defined by the type descriptor.
  /// @param valid   `true` to mark the bit valid, `false` to mark it invalid. Defaults to `true`.
  /// @throws UaException `BadInvalidArgument` if @p bitName is unknown to the descriptor, or
  ///         `BadOutOfRange` if its bit number is negative.
  void set_valid(string_view bitName, bool valid = true);

  // --- Introspection ---

  /// Returns the type descriptor bound to this option set.
  ///
  /// The reference is valid for the lifetime of this instance.
  /// @return The @ref DynamicEnumTypeDescriptor bound to this option set.
  const DynamicEnumTypeDescriptor& descriptor() const;

private:
  shared_ptr<const DynamicEnumTypeDescriptor> mDescriptor;

  int64_t require_bit_number(string_view bitName) const;
  static bool get_bit(const ByteString& bytes, int64_t bitNumber);
  static void set_bit_in(ByteString& bytes, int64_t bitNumber, bool bitValue);
};

}  // namespace ua

#endif  // !UA_DYNAMIC_OPTION_SET_H
