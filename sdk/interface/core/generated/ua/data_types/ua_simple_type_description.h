// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_SIMPLE_TYPE_DESCRIPTION_H
#define UA_DATA_TYPE_SIMPLE_TYPE_DESCRIPTION_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_data_type_description.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_node_id.h"

namespace ua
{

class StructureFactory;

/// OPC UA SimpleTypeDescription structured data type.
/// @ingroup ua_data_types
class SimpleTypeDescription : public DataTypeDescription
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"SimpleTypeDescription"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::SimpleTypeDescription};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::SimpleTypeDescription_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::SimpleTypeDescription_Encoding_DefaultXml};

  /// Constructs a `SimpleTypeDescription` with all fields value-initialised.
  SimpleTypeDescription() = default;
  /// Defaulted copy: `SimpleTypeDescription` is a value type (memberwise copy).
  /// @param other The value to copy from.
  SimpleTypeDescription(const SimpleTypeDescription& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  SimpleTypeDescription(SimpleTypeDescription&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  SimpleTypeDescription& operator=(const SimpleTypeDescription& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  SimpleTypeDescription& operator=(SimpleTypeDescription&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~SimpleTypeDescription() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const SimpleTypeDescription& obj) const = default;

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

  /// Accesses the `BaseDataType` field.
  /// @return A mutable reference to the `BaseDataType` field.
  NodeId& base_data_type();
  /// @return A const reference to the `BaseDataType` field.
  const NodeId& base_data_type() const;

  /// Accesses the `BuiltInType` field.
  /// @return A mutable reference to the `BuiltInType` field.
  uint8_t& built_in_type();
  /// @return A const reference to the `BuiltInType` field.
  const uint8_t& built_in_type() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  NodeId mBaseDataType{};  ///< Base data type.
  uint8_t mBuiltInType{};  ///< Built in type.
};

template<>
inline string_view get_typename<SimpleTypeDescription>()
{
  return SimpleTypeDescription::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_SIMPLE_TYPE_DESCRIPTION_H
