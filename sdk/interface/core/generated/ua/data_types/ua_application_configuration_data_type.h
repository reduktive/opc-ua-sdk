// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_APPLICATION_CONFIGURATION_DATA_TYPE_H
#define UA_DATA_TYPE_APPLICATION_CONFIGURATION_DATA_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_base_configuration_data_type.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_application_identity_data_type.h"
#include "ua_certificate_group_data_type.h"
#include "ua_server_endpoint_data_type.h"
#include "ua_endpoint_data_type.h"
#include "ua_security_settings_data_type.h"
#include "ua_user_token_settings_data_type.h"
#include "ua_authorization_service_configuration_data_type.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA ApplicationConfigurationDataType structured data type.
/// @ingroup ua_data_types
class ApplicationConfigurationDataType : public BaseConfigurationDataType
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"ApplicationConfigurationDataType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::ApplicationConfigurationDataType};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{
    ObjectId::ApplicationConfigurationDataType_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::ApplicationConfigurationDataType_Encoding_DefaultXml};

  /// Constructs a `ApplicationConfigurationDataType` with all fields value-initialised.
  ApplicationConfigurationDataType() = default;
  /// Defaulted copy: `ApplicationConfigurationDataType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  ApplicationConfigurationDataType(const ApplicationConfigurationDataType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  ApplicationConfigurationDataType(ApplicationConfigurationDataType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  ApplicationConfigurationDataType& operator=(const ApplicationConfigurationDataType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  ApplicationConfigurationDataType& operator=(ApplicationConfigurationDataType&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~ApplicationConfigurationDataType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const ApplicationConfigurationDataType& obj) const = default;

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

  /// Accesses the `ApplicationIdentity` field.
  /// @return A mutable reference to the `ApplicationIdentity` field.
  ApplicationIdentityDataType& application_identity();
  /// @return A const reference to the `ApplicationIdentity` field.
  const ApplicationIdentityDataType& application_identity() const;

  /// Accesses the `CertificateGroups` field.
  /// @return A mutable reference to the `CertificateGroups` field.
  Array<CertificateGroupDataType>& certificate_groups();
  /// @return A const reference to the `CertificateGroups` field.
  const Array<CertificateGroupDataType>& certificate_groups() const;

  /// Accesses the `ServerEndpoints` field.
  /// @return A mutable reference to the `ServerEndpoints` field.
  Array<ServerEndpointDataType>& server_endpoints();
  /// @return A const reference to the `ServerEndpoints` field.
  const Array<ServerEndpointDataType>& server_endpoints() const;

  /// Accesses the `ClientEndpoints` field.
  /// @return A mutable reference to the `ClientEndpoints` field.
  Array<EndpointDataType>& client_endpoints();
  /// @return A const reference to the `ClientEndpoints` field.
  const Array<EndpointDataType>& client_endpoints() const;

  /// Accesses the `SecuritySettings` field.
  /// @return A mutable reference to the `SecuritySettings` field.
  Array<SecuritySettingsDataType>& security_settings();
  /// @return A const reference to the `SecuritySettings` field.
  const Array<SecuritySettingsDataType>& security_settings() const;

  /// Accesses the `UserTokenSettings` field.
  /// @return A mutable reference to the `UserTokenSettings` field.
  Array<UserTokenSettingsDataType>& user_token_settings();
  /// @return A const reference to the `UserTokenSettings` field.
  const Array<UserTokenSettingsDataType>& user_token_settings() const;

  /// Accesses the `AuthorizationServices` field.
  /// @return A mutable reference to the `AuthorizationServices` field.
  Array<AuthorizationServiceConfigurationDataType>& authorization_services();
  /// @return A const reference to the `AuthorizationServices` field.
  const Array<AuthorizationServiceConfigurationDataType>& authorization_services() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  ApplicationIdentityDataType mApplicationIdentity{};  ///< Application identity.
  Array<CertificateGroupDataType> mCertificateGroups{};  ///< Certificate groups.
  Array<ServerEndpointDataType> mServerEndpoints{};  ///< Server endpoints.
  Array<EndpointDataType> mClientEndpoints{};  ///< Client endpoints.
  Array<SecuritySettingsDataType> mSecuritySettings{};  ///< Security settings.
  Array<UserTokenSettingsDataType> mUserTokenSettings{};  ///< User token settings.
  Array<AuthorizationServiceConfigurationDataType> mAuthorizationServices{};  ///< Authorization services.
};

template<>
inline string_view get_typename<ApplicationConfigurationDataType>()
{
  return ApplicationConfigurationDataType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_APPLICATION_CONFIGURATION_DATA_TYPE_H
