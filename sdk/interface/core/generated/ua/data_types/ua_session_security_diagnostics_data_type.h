// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_SESSION_SECURITY_DIAGNOSTICS_DATA_TYPE_H
#define UA_DATA_TYPE_SESSION_SECURITY_DIAGNOSTICS_DATA_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_node_id.h"
#include "ua_string.h"
#include "ua_message_security_mode.h"
#include "ua_byte_string.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA SessionSecurityDiagnosticsDataType structured data type.
/// @ingroup ua_data_types
class SessionSecurityDiagnosticsDataType : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"SessionSecurityDiagnosticsDataType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::SessionSecurityDiagnosticsDataType};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{
    ObjectId::SessionSecurityDiagnosticsDataType_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{
    ObjectId::SessionSecurityDiagnosticsDataType_Encoding_DefaultXml};

  /// Constructs a `SessionSecurityDiagnosticsDataType` with all fields value-initialised.
  SessionSecurityDiagnosticsDataType() = default;
  /// Defaulted copy: `SessionSecurityDiagnosticsDataType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  SessionSecurityDiagnosticsDataType(const SessionSecurityDiagnosticsDataType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  SessionSecurityDiagnosticsDataType(SessionSecurityDiagnosticsDataType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  SessionSecurityDiagnosticsDataType& operator=(const SessionSecurityDiagnosticsDataType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  SessionSecurityDiagnosticsDataType& operator=(
    SessionSecurityDiagnosticsDataType&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~SessionSecurityDiagnosticsDataType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const SessionSecurityDiagnosticsDataType& obj) const = default;

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

  /// Accesses the `SessionId` field.
  /// @return A mutable reference to the `SessionId` field.
  NodeId& session_id();
  /// @return A const reference to the `SessionId` field.
  const NodeId& session_id() const;

  /// Accesses the `ClientUserIdOfSession` field.
  /// @return A mutable reference to the `ClientUserIdOfSession` field.
  String& client_user_id_of_session();
  /// @return A const reference to the `ClientUserIdOfSession` field.
  const String& client_user_id_of_session() const;

  /// Accesses the `ClientUserIdHistory` field.
  /// @return A mutable reference to the `ClientUserIdHistory` field.
  Array<String>& client_user_id_history();
  /// @return A const reference to the `ClientUserIdHistory` field.
  const Array<String>& client_user_id_history() const;

  /// Accesses the `AuthenticationMechanism` field.
  /// @return A mutable reference to the `AuthenticationMechanism` field.
  String& authentication_mechanism();
  /// @return A const reference to the `AuthenticationMechanism` field.
  const String& authentication_mechanism() const;

  /// Accesses the `Encoding` field.
  /// @return A mutable reference to the `Encoding` field.
  String& encoding();
  /// @return A const reference to the `Encoding` field.
  const String& encoding() const;

  /// Accesses the `TransportProtocol` field.
  /// @return A mutable reference to the `TransportProtocol` field.
  String& transport_protocol();
  /// @return A const reference to the `TransportProtocol` field.
  const String& transport_protocol() const;

  /// Accesses the `SecurityMode` field.
  /// @return A mutable reference to the `SecurityMode` field.
  MessageSecurityMode& security_mode();
  /// @return A const reference to the `SecurityMode` field.
  const MessageSecurityMode& security_mode() const;

  /// Accesses the `SecurityPolicyUri` field.
  /// @return A mutable reference to the `SecurityPolicyUri` field.
  String& security_policy_uri();
  /// @return A const reference to the `SecurityPolicyUri` field.
  const String& security_policy_uri() const;

  /// Accesses the `ClientCertificate` field.
  /// @return A mutable reference to the `ClientCertificate` field.
  ByteString& client_certificate();
  /// @return A const reference to the `ClientCertificate` field.
  const ByteString& client_certificate() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  NodeId mSessionId{};  ///< Session ID.
  String mClientUserIdOfSession{};  ///< Client user ID of session.
  Array<String> mClientUserIdHistory{};  ///< Client user ID history.
  String mAuthenticationMechanism{};  ///< Authentication mechanism.
  String mEncoding{};  ///< Encoding.
  String mTransportProtocol{};  ///< Transport protocol.
  MessageSecurityMode mSecurityMode{};  ///< Security mode.
  String mSecurityPolicyUri{};  ///< Security policy URI.
  ByteString mClientCertificate{};  ///< Client certificate.
};

template<>
inline string_view get_typename<SessionSecurityDiagnosticsDataType>()
{
  return SessionSecurityDiagnosticsDataType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_SESSION_SECURITY_DIAGNOSTICS_DATA_TYPE_H
