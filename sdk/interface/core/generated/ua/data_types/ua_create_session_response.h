// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_CREATE_SESSION_RESPONSE_H
#define UA_DATA_TYPE_CREATE_SESSION_RESPONSE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_response_header.h"
#include "ua_node_id.h"
#include "ua_session_authentication_token.h"
#include "ua_duration.h"
#include "ua_byte_string.h"
#include "ua_application_instance_certificate.h"
#include "ua_endpoint_description.h"
#include "ua_signed_software_certificate.h"
#include "ua_signature_data.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA CreateSessionResponse response structure.
/// @ingroup ua_data_types
class CreateSessionResponse : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"CreateSessionResponse"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::CreateSessionResponse};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::CreateSessionResponse_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::CreateSessionResponse_Encoding_DefaultXml};

  /// Constructs a `CreateSessionResponse` with all fields value-initialised.
  CreateSessionResponse() = default;
  /// Defaulted copy: `CreateSessionResponse` is a value type (memberwise copy).
  /// @param other The value to copy from.
  CreateSessionResponse(const CreateSessionResponse& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  CreateSessionResponse(CreateSessionResponse&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  CreateSessionResponse& operator=(const CreateSessionResponse& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  CreateSessionResponse& operator=(CreateSessionResponse&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~CreateSessionResponse() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const CreateSessionResponse& obj) const = default;

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

  /// Accesses the `ResponseHeader` field.
  /// @return A mutable reference to the `ResponseHeader` field.
  ResponseHeader& response_header();
  /// @return A const reference to the `ResponseHeader` field.
  const ResponseHeader& response_header() const;

  /// Accesses the `SessionId` field.
  /// @return A mutable reference to the `SessionId` field.
  NodeId& session_id();
  /// @return A const reference to the `SessionId` field.
  const NodeId& session_id() const;

  /// Accesses the `AuthenticationToken` field.
  /// @return A mutable reference to the `AuthenticationToken` field.
  SessionAuthenticationToken& authentication_token();
  /// @return A const reference to the `AuthenticationToken` field.
  const SessionAuthenticationToken& authentication_token() const;

  /// Accesses the `RevisedSessionTimeout` field.
  /// @return A mutable reference to the `RevisedSessionTimeout` field.
  Duration& revised_session_timeout();
  /// @return A const reference to the `RevisedSessionTimeout` field.
  const Duration& revised_session_timeout() const;

  /// Accesses the `ServerNonce` field.
  /// @return A mutable reference to the `ServerNonce` field.
  ByteString& server_nonce();
  /// @return A const reference to the `ServerNonce` field.
  const ByteString& server_nonce() const;

  /// Accesses the `ServerCertificate` field.
  /// @return A mutable reference to the `ServerCertificate` field.
  ApplicationInstanceCertificate& server_certificate();
  /// @return A const reference to the `ServerCertificate` field.
  const ApplicationInstanceCertificate& server_certificate() const;

  /// Accesses the `ServerEndpoints` field.
  /// @return A mutable reference to the `ServerEndpoints` field.
  Array<EndpointDescription>& server_endpoints();
  /// @return A const reference to the `ServerEndpoints` field.
  const Array<EndpointDescription>& server_endpoints() const;

  /// Accesses the `ServerSoftwareCertificates` field.
  /// @return A mutable reference to the `ServerSoftwareCertificates` field.
  Array<SignedSoftwareCertificate>& server_software_certificates();
  /// @return A const reference to the `ServerSoftwareCertificates` field.
  const Array<SignedSoftwareCertificate>& server_software_certificates() const;

  /// Accesses the `ServerSignature` field.
  /// @return A mutable reference to the `ServerSignature` field.
  SignatureData& server_signature();
  /// @return A const reference to the `ServerSignature` field.
  const SignatureData& server_signature() const;

  /// Accesses the `MaxRequestMessageSize` field.
  /// @return A mutable reference to the `MaxRequestMessageSize` field.
  uint32_t& max_request_message_size();
  /// @return A const reference to the `MaxRequestMessageSize` field.
  const uint32_t& max_request_message_size() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  ResponseHeader mResponseHeader{};  ///< Response header.
  NodeId mSessionId{};  ///< Session ID.
  SessionAuthenticationToken mAuthenticationToken{};  ///< Authentication token.
  Duration mRevisedSessionTimeout{};  ///< Revised session timeout.
  ByteString mServerNonce{};  ///< Server nonce.
  ApplicationInstanceCertificate mServerCertificate{};  ///< Server certificate.
  Array<EndpointDescription> mServerEndpoints{};  ///< Server endpoints.
  Array<SignedSoftwareCertificate> mServerSoftwareCertificates{};  ///< Server software certificates.
  SignatureData mServerSignature{};  ///< Server signature.
  uint32_t mMaxRequestMessageSize{};  ///< Max request message size.
};

template<>
inline string_view get_typename<CreateSessionResponse>()
{
  return CreateSessionResponse::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_CREATE_SESSION_RESPONSE_H
