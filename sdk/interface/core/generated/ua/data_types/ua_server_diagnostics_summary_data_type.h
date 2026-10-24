// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_SERVER_DIAGNOSTICS_SUMMARY_DATA_TYPE_H
#define UA_DATA_TYPE_SERVER_DIAGNOSTICS_SUMMARY_DATA_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"

namespace ua
{

class StructureFactory;

/// OPC UA ServerDiagnosticsSummaryDataType structured data type.
/// @ingroup ua_data_types
class ServerDiagnosticsSummaryDataType : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"ServerDiagnosticsSummaryDataType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::ServerDiagnosticsSummaryDataType};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{
    ObjectId::ServerDiagnosticsSummaryDataType_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::ServerDiagnosticsSummaryDataType_Encoding_DefaultXml};

  /// Constructs a `ServerDiagnosticsSummaryDataType` with all fields value-initialised.
  ServerDiagnosticsSummaryDataType() = default;
  /// Defaulted copy: `ServerDiagnosticsSummaryDataType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  ServerDiagnosticsSummaryDataType(const ServerDiagnosticsSummaryDataType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  ServerDiagnosticsSummaryDataType(ServerDiagnosticsSummaryDataType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  ServerDiagnosticsSummaryDataType& operator=(const ServerDiagnosticsSummaryDataType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  ServerDiagnosticsSummaryDataType& operator=(ServerDiagnosticsSummaryDataType&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~ServerDiagnosticsSummaryDataType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const ServerDiagnosticsSummaryDataType& obj) const = default;

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

  /// Accesses the `ServerViewCount` field.
  /// @return A mutable reference to the `ServerViewCount` field.
  uint32_t& server_view_count();
  /// @return A const reference to the `ServerViewCount` field.
  const uint32_t& server_view_count() const;

  /// Accesses the `CurrentSessionCount` field.
  /// @return A mutable reference to the `CurrentSessionCount` field.
  uint32_t& current_session_count();
  /// @return A const reference to the `CurrentSessionCount` field.
  const uint32_t& current_session_count() const;

  /// Accesses the `CumulatedSessionCount` field.
  /// @return A mutable reference to the `CumulatedSessionCount` field.
  uint32_t& cumulated_session_count();
  /// @return A const reference to the `CumulatedSessionCount` field.
  const uint32_t& cumulated_session_count() const;

  /// Accesses the `SecurityRejectedSessionCount` field.
  /// @return A mutable reference to the `SecurityRejectedSessionCount` field.
  uint32_t& security_rejected_session_count();
  /// @return A const reference to the `SecurityRejectedSessionCount` field.
  const uint32_t& security_rejected_session_count() const;

  /// Accesses the `RejectedSessionCount` field.
  /// @return A mutable reference to the `RejectedSessionCount` field.
  uint32_t& rejected_session_count();
  /// @return A const reference to the `RejectedSessionCount` field.
  const uint32_t& rejected_session_count() const;

  /// Accesses the `SessionTimeoutCount` field.
  /// @return A mutable reference to the `SessionTimeoutCount` field.
  uint32_t& session_timeout_count();
  /// @return A const reference to the `SessionTimeoutCount` field.
  const uint32_t& session_timeout_count() const;

  /// Accesses the `SessionAbortCount` field.
  /// @return A mutable reference to the `SessionAbortCount` field.
  uint32_t& session_abort_count();
  /// @return A const reference to the `SessionAbortCount` field.
  const uint32_t& session_abort_count() const;

  /// Accesses the `CurrentSubscriptionCount` field.
  /// @return A mutable reference to the `CurrentSubscriptionCount` field.
  uint32_t& current_subscription_count();
  /// @return A const reference to the `CurrentSubscriptionCount` field.
  const uint32_t& current_subscription_count() const;

  /// Accesses the `CumulatedSubscriptionCount` field.
  /// @return A mutable reference to the `CumulatedSubscriptionCount` field.
  uint32_t& cumulated_subscription_count();
  /// @return A const reference to the `CumulatedSubscriptionCount` field.
  const uint32_t& cumulated_subscription_count() const;

  /// Accesses the `PublishingIntervalCount` field.
  /// @return A mutable reference to the `PublishingIntervalCount` field.
  uint32_t& publishing_interval_count();
  /// @return A const reference to the `PublishingIntervalCount` field.
  const uint32_t& publishing_interval_count() const;

  /// Accesses the `SecurityRejectedRequestsCount` field.
  /// @return A mutable reference to the `SecurityRejectedRequestsCount` field.
  uint32_t& security_rejected_requests_count();
  /// @return A const reference to the `SecurityRejectedRequestsCount` field.
  const uint32_t& security_rejected_requests_count() const;

  /// Accesses the `RejectedRequestsCount` field.
  /// @return A mutable reference to the `RejectedRequestsCount` field.
  uint32_t& rejected_requests_count();
  /// @return A const reference to the `RejectedRequestsCount` field.
  const uint32_t& rejected_requests_count() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  uint32_t mServerViewCount{};  ///< Server view count.
  uint32_t mCurrentSessionCount{};  ///< Current session count.
  uint32_t mCumulatedSessionCount{};  ///< Cumulated session count.
  uint32_t mSecurityRejectedSessionCount{};  ///< Security rejected session count.
  uint32_t mRejectedSessionCount{};  ///< Rejected session count.
  uint32_t mSessionTimeoutCount{};  ///< Session timeout count.
  uint32_t mSessionAbortCount{};  ///< Session abort count.
  uint32_t mCurrentSubscriptionCount{};  ///< Current subscription count.
  uint32_t mCumulatedSubscriptionCount{};  ///< Cumulated subscription count.
  uint32_t mPublishingIntervalCount{};  ///< Publishing interval count.
  uint32_t mSecurityRejectedRequestsCount{};  ///< Security rejected requests count.
  uint32_t mRejectedRequestsCount{};  ///< Rejected requests count.
};

template<>
inline string_view get_typename<ServerDiagnosticsSummaryDataType>()
{
  return ServerDiagnosticsSummaryDataType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_SERVER_DIAGNOSTICS_SUMMARY_DATA_TYPE_H
