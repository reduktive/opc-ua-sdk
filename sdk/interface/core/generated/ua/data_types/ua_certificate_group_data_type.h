// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_CERTIFICATE_GROUP_DATA_TYPE_H
#define UA_DATA_TYPE_CERTIFICATE_GROUP_DATA_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_base_configuration_record_data_type.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_node_id.h"
#include "ua_trust_list_validation_options.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA CertificateGroupDataType structured data type.
/// @ingroup ua_data_types
class CertificateGroupDataType : public BaseConfigurationRecordDataType
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"CertificateGroupDataType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::CertificateGroupDataType};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::CertificateGroupDataType_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::CertificateGroupDataType_Encoding_DefaultXml};

  /// Constructs a `CertificateGroupDataType` with all fields value-initialised.
  CertificateGroupDataType() = default;
  /// Defaulted copy: `CertificateGroupDataType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  CertificateGroupDataType(const CertificateGroupDataType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  CertificateGroupDataType(CertificateGroupDataType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  CertificateGroupDataType& operator=(const CertificateGroupDataType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  CertificateGroupDataType& operator=(CertificateGroupDataType&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~CertificateGroupDataType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const CertificateGroupDataType& obj) const = default;

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

  /// Accesses the `Purpose` field.
  /// @return A mutable reference to the `Purpose` field.
  NodeId& purpose();
  /// @return A const reference to the `Purpose` field.
  const NodeId& purpose() const;

  /// Accesses the `CertificateTypes` field.
  /// @return A mutable reference to the `CertificateTypes` field.
  Array<NodeId>& certificate_types();
  /// @return A const reference to the `CertificateTypes` field.
  const Array<NodeId>& certificate_types() const;

  /// Accesses the `IsCertificateAssigned` field.
  /// @return A mutable reference to the `IsCertificateAssigned` field.
  Array<bool>& is_certificate_assigned();
  /// @return A const reference to the `IsCertificateAssigned` field.
  const Array<bool>& is_certificate_assigned() const;

  /// Accesses the `ValidationOptions` field.
  /// @return A mutable reference to the `ValidationOptions` field.
  TrustListValidationOptions& validation_options();
  /// @return A const reference to the `ValidationOptions` field.
  const TrustListValidationOptions& validation_options() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  NodeId mPurpose{};  ///< Purpose.
  Array<NodeId> mCertificateTypes{};  ///< Certificate types.
  Array<bool> mIsCertificateAssigned{};  ///< Is certificate assigned.
  TrustListValidationOptions mValidationOptions{};  ///< Validation options.
};

template<>
inline string_view get_typename<CertificateGroupDataType>()
{
  return CertificateGroupDataType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_CERTIFICATE_GROUP_DATA_TYPE_H
