// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_NODE_ATTRIBUTES_H
#define UA_DATA_TYPE_NODE_ATTRIBUTES_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_localized_text.h"

namespace ua
{

class StructureFactory;

/// OPC UA NodeAttributes structured data type.
/// @ingroup ua_data_types
class NodeAttributes : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"NodeAttributes"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::NodeAttributes};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::NodeAttributes_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::NodeAttributes_Encoding_DefaultXml};

  /// Constructs a `NodeAttributes` with all fields value-initialised.
  NodeAttributes() = default;
  /// Defaulted copy: `NodeAttributes` is a value type (memberwise copy).
  /// @param other The value to copy from.
  NodeAttributes(const NodeAttributes& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  NodeAttributes(NodeAttributes&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  NodeAttributes& operator=(const NodeAttributes& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  NodeAttributes& operator=(NodeAttributes&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~NodeAttributes() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const NodeAttributes& obj) const = default;

  /// Tests whether this value's type matches `dataTypeId` or one of its supertypes.
  /// @param ns     Namespace context used to resolve `dataTypeId`.
  /// @param dataTypeId Candidate type identifier.
  /// @return `true` if this value is of type `dataTypeId` or a subtype of it.
  bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const override;

  /// @return The type's `ExpandedNodeId`.
  ExpandedNodeId type_id() const override;

  /// Resolves the type's `NodeId` in a namespace context.
  /// @param ns Namespace context supplying the runtime namespace index.
  /// @return The type's `NodeId`.
  NodeId type_id(const CodecNamespaceContext& ns) const override;

  /// @return The unqualified OPC UA type name.
  String type_name() const override;

  /// Encodes the type's encoding id.
  /// @param limit   Remaining stack-depth budget guarding against deep nesting.
  /// @param ns      Namespace context used to resolve the encoding id.
  /// @param encoder Sink the encoding id is written to.
  void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const override;

  /// Encodes this value's fields.
  /// @param limit   Remaining stack-depth budget guarding against deep nesting.
  /// @param encoder Sink the fields are written to.
  void encode(StackDepth limit, Encoder& encoder) const override;

  /// Decodes this value's fields, replacing the current contents.
  /// @param limit   Remaining stack-depth budget guarding against deep nesting.
  /// @param decoder Source the fields are read from.
  void decode(StackDepth limit, Decoder& decoder) override;

  /// Resolves this value's localized-text fields to the preferred locales.
  /// @param locales Preferred locales, most-preferred first.
  void resolve(span<const LocaleId> locales) override;

  /// Polymorphically deep-copies this value.
  /// @return A heap-allocated copy held by its `Structure` base.
  unique_ptr<Structure> clone() const override;

  /// Formats this value as human-readable text, for logging and debugging.
  /// @param indent Indentation depth applied to nested structures.
  /// @return The formatted representation.
  std::string to_string(int indent = 0) const override;

  /// Registers this type's decode factories so encoded values can be
  /// reconstructed by their encoding id.
  /// @param ns              Namespace context the encoding ids are registered under.
  /// @param uaBinaryFactory Binary-codec factory to register with, or null to skip.
  /// @param xmlFactory      XML-codec factory to register with, or null to skip.
  static void register_type(
    const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);

  /// Accesses the `SpecifiedAttributes` field.
  /// @return A mutable reference to the `SpecifiedAttributes` field.
  uint32_t& specified_attributes();
  /// @return A const reference to the `SpecifiedAttributes` field.
  const uint32_t& specified_attributes() const;

  /// Accesses the `DisplayName` field.
  /// @return A mutable reference to the `DisplayName` field.
  LocalizedText& display_name();
  /// @return A const reference to the `DisplayName` field.
  const LocalizedText& display_name() const;

  /// Accesses the `Description` field.
  /// @return A mutable reference to the `Description` field.
  LocalizedText& description();
  /// @return A const reference to the `Description` field.
  const LocalizedText& description() const;

  /// Accesses the `WriteMask` field.
  /// @return A mutable reference to the `WriteMask` field.
  uint32_t& write_mask();
  /// @return A const reference to the `WriteMask` field.
  const uint32_t& write_mask() const;

  /// Accesses the `UserWriteMask` field.
  /// @return A mutable reference to the `UserWriteMask` field.
  uint32_t& user_write_mask();
  /// @return A const reference to the `UserWriteMask` field.
  const uint32_t& user_write_mask() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  uint32_t mSpecifiedAttributes{};  ///< Specified attributes.
  LocalizedText mDisplayName{};  ///< Display name.
  LocalizedText mDescription{};  ///< Description.
  uint32_t mWriteMask{};  ///< Write mask.
  uint32_t mUserWriteMask{};  ///< User write mask.
};

template<>
inline string_view get_typename<NodeAttributes>()
{
  return NodeAttributes::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_NODE_ATTRIBUTES_H
