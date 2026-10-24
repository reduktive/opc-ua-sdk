// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_SERVER_ENDPOINT_DATA_TYPE_H
#define UA_DATA_TYPE_SERVER_ENDPOINT_DATA_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_endpoint_data_type.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_uri_string.h"
#include "ua_string.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA ServerEndpointDataType structured data type.
/// @ingroup ua_data_types
class ServerEndpointDataType : public EndpointDataType
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"ServerEndpointDataType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::ServerEndpointDataType};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::ServerEndpointDataType_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::ServerEndpointDataType_Encoding_DefaultXml};

  /// Constructs a `ServerEndpointDataType` with all fields value-initialised.
  ServerEndpointDataType() = default;
  /// Defaulted copy: `ServerEndpointDataType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  ServerEndpointDataType(const ServerEndpointDataType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  ServerEndpointDataType(ServerEndpointDataType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  ServerEndpointDataType& operator=(const ServerEndpointDataType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  ServerEndpointDataType& operator=(ServerEndpointDataType&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~ServerEndpointDataType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const ServerEndpointDataType& obj) const = default;

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

  /// Accesses the `EndpointUrls` field.
  /// @return A mutable reference to the `EndpointUrls` field.
  Array<UriString>& endpoint_urls();
  /// @return A const reference to the `EndpointUrls` field.
  const Array<UriString>& endpoint_urls() const;

  /// Accesses the `SecuritySettingNames` field.
  /// @return A mutable reference to the `SecuritySettingNames` field.
  Array<String>& security_setting_names();
  /// @return A const reference to the `SecuritySettingNames` field.
  const Array<String>& security_setting_names() const;

  /// Accesses the `TransportProfileUri` field.
  /// @return A mutable reference to the `TransportProfileUri` field.
  UriString& transport_profile_uri();
  /// @return A const reference to the `TransportProfileUri` field.
  const UriString& transport_profile_uri() const;

  /// Accesses the `UserTokenSettingNames` field.
  /// @return A mutable reference to the `UserTokenSettingNames` field.
  Array<String>& user_token_setting_names();
  /// @return A const reference to the `UserTokenSettingNames` field.
  const Array<String>& user_token_setting_names() const;

  /// Accesses the `ReverseConnectUrls` field.
  /// @return A mutable reference to the `ReverseConnectUrls` field.
  Array<String>& reverse_connect_urls();
  /// @return A const reference to the `ReverseConnectUrls` field.
  const Array<String>& reverse_connect_urls() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  Array<UriString> mEndpointUrls{};  ///< Endpoint urls.
  Array<String> mSecuritySettingNames{};  ///< Security setting names.
  UriString mTransportProfileUri{};  ///< Transport profile URI.
  Array<String> mUserTokenSettingNames{};  ///< User token setting names.
  Array<String> mReverseConnectUrls{};  ///< Reverse connect urls.
};

template<>
inline string_view get_typename<ServerEndpointDataType>()
{
  return ServerEndpointDataType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_SERVER_ENDPOINT_DATA_TYPE_H
