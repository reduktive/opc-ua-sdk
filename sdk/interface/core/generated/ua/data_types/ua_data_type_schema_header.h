// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_DATA_TYPE_SCHEMA_HEADER_H
#define UA_DATA_TYPE_DATA_TYPE_SCHEMA_HEADER_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_string.h"
#include "ua_structure_description.h"
#include "ua_enum_description.h"
#include "ua_simple_type_description.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA DataTypeSchemaHeader structured data type.
/// @ingroup ua_data_types
class DataTypeSchemaHeader : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"DataTypeSchemaHeader"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::DataTypeSchemaHeader};

protected:
  /// Constructs a `DataTypeSchemaHeader` with all fields value-initialised.
  DataTypeSchemaHeader() = default;
  /// Defaulted copy: `DataTypeSchemaHeader` is a value type (memberwise copy).
  /// @param other The value to copy from.
  DataTypeSchemaHeader(const DataTypeSchemaHeader& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  DataTypeSchemaHeader(DataTypeSchemaHeader&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  DataTypeSchemaHeader& operator=(const DataTypeSchemaHeader& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  DataTypeSchemaHeader& operator=(DataTypeSchemaHeader&& other) noexcept = default;

public:
  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~DataTypeSchemaHeader() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const DataTypeSchemaHeader& obj) const = default;

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

  /// Accesses the `Namespaces` field.
  /// @return A mutable reference to the `Namespaces` field.
  Array<String>& namespaces();
  /// @return A const reference to the `Namespaces` field.
  const Array<String>& namespaces() const;

  /// Accesses the `StructureDataTypes` field.
  /// @return A mutable reference to the `StructureDataTypes` field.
  Array<StructureDescription>& structure_data_types();
  /// @return A const reference to the `StructureDataTypes` field.
  const Array<StructureDescription>& structure_data_types() const;

  /// Accesses the `EnumDataTypes` field.
  /// @return A mutable reference to the `EnumDataTypes` field.
  Array<EnumDescription>& enum_data_types();
  /// @return A const reference to the `EnumDataTypes` field.
  const Array<EnumDescription>& enum_data_types() const;

  /// Accesses the `SimpleDataTypes` field.
  /// @return A mutable reference to the `SimpleDataTypes` field.
  Array<SimpleTypeDescription>& simple_data_types();
  /// @return A const reference to the `SimpleDataTypes` field.
  const Array<SimpleTypeDescription>& simple_data_types() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  Array<String> mNamespaces{};  ///< Namespaces.
  Array<StructureDescription> mStructureDataTypes{};  ///< Structure data types.
  Array<EnumDescription> mEnumDataTypes{};  ///< Enum data types.
  Array<SimpleTypeDescription> mSimpleDataTypes{};  ///< Simple data types.
};

template<>
inline string_view get_typename<DataTypeSchemaHeader>()
{
  return DataTypeSchemaHeader::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_DATA_TYPE_SCHEMA_HEADER_H
