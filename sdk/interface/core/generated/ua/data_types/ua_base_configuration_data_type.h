// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_BASE_CONFIGURATION_DATA_TYPE_H
#define UA_DATA_TYPE_BASE_CONFIGURATION_DATA_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_version_time.h"
#include "ua_key_value_pair.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA BaseConfigurationDataType structured data type.
/// @ingroup ua_data_types
class BaseConfigurationDataType : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"BaseConfigurationDataType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::BaseConfigurationDataType};

protected:
  /// Constructs a `BaseConfigurationDataType` with all fields value-initialised.
  BaseConfigurationDataType() = default;
  /// Defaulted copy: `BaseConfigurationDataType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  BaseConfigurationDataType(const BaseConfigurationDataType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  BaseConfigurationDataType(BaseConfigurationDataType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  BaseConfigurationDataType& operator=(const BaseConfigurationDataType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  BaseConfigurationDataType& operator=(BaseConfigurationDataType&& other) noexcept = default;

public:
  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~BaseConfigurationDataType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const BaseConfigurationDataType& obj) const = default;

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

  /// Accesses the `ConfigurationVersion` field.
  /// @return A mutable reference to the `ConfigurationVersion` field.
  VersionTime& configuration_version();
  /// @return A const reference to the `ConfigurationVersion` field.
  const VersionTime& configuration_version() const;

  /// Accesses the `ConfigurationProperties` field.
  /// @return A mutable reference to the `ConfigurationProperties` field.
  Array<KeyValuePair>& configuration_properties();
  /// @return A const reference to the `ConfigurationProperties` field.
  const Array<KeyValuePair>& configuration_properties() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  VersionTime mConfigurationVersion{};  ///< Configuration version.
  Array<KeyValuePair> mConfigurationProperties{};  ///< Configuration properties.
};

template<>
inline string_view get_typename<BaseConfigurationDataType>()
{
  return BaseConfigurationDataType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_BASE_CONFIGURATION_DATA_TYPE_H
