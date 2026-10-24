// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_LOG_RECORD_H
#define UA_DATA_TYPE_LOG_RECORD_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_date_time.h"
#include "ua_node_id.h"
#include "ua_string.h"
#include "ua_localized_text.h"
#include "ua_trace_context_data_type.h"
#include "ua_name_value_pair.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA LogRecord structured data type.
/// @ingroup ua_data_types
class LogRecord : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"LogRecord"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::LogRecord};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::LogRecord_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::LogRecord_Encoding_DefaultXml};

  /// Constructs a `LogRecord` with all fields value-initialised.
  LogRecord() = default;
  /// Defaulted copy: `LogRecord` is a value type (memberwise copy).
  /// @param other The value to copy from.
  LogRecord(const LogRecord& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  LogRecord(LogRecord&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  LogRecord& operator=(const LogRecord& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  LogRecord& operator=(LogRecord&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~LogRecord() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const LogRecord& obj) const = default;

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

  /// Accesses the `Time` field.
  /// @return A mutable reference to the `Time` field.
  DateTime& time();
  /// @return A const reference to the `Time` field.
  const DateTime& time() const;

  /// Accesses the `Severity` field.
  /// @return A mutable reference to the `Severity` field.
  uint16_t& severity();
  /// @return A const reference to the `Severity` field.
  const uint16_t& severity() const;

  /// Accesses the `EventType` field.
  /// @return A mutable reference to the `EventType` field.
  optional<NodeId>& event_type();
  /// @return A const reference to the `EventType` field.
  const optional<NodeId>& event_type() const;

  /// Accesses the `SourceNode` field.
  /// @return A mutable reference to the `SourceNode` field.
  optional<NodeId>& source_node();
  /// @return A const reference to the `SourceNode` field.
  const optional<NodeId>& source_node() const;

  /// Accesses the `SourceName` field.
  /// @return A mutable reference to the `SourceName` field.
  optional<String>& source_name();
  /// @return A const reference to the `SourceName` field.
  const optional<String>& source_name() const;

  /// Accesses the `Message` field.
  /// @return A mutable reference to the `Message` field.
  LocalizedText& message();
  /// @return A const reference to the `Message` field.
  const LocalizedText& message() const;

  /// Accesses the `TraceContext` field.
  /// @return A mutable reference to the `TraceContext` field.
  optional<TraceContextDataType>& trace_context();
  /// @return A const reference to the `TraceContext` field.
  const optional<TraceContextDataType>& trace_context() const;

  /// Accesses the `AdditionalData` field.
  /// @return A mutable reference to the `AdditionalData` field.
  optional<Array<NameValuePair>>& additional_data();
  /// @return A const reference to the `AdditionalData` field.
  const optional<Array<NameValuePair>>& additional_data() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  DateTime mTime{};  ///< Time.
  uint16_t mSeverity{};  ///< Severity.
  optional<NodeId> mEventType{};  ///< Event type.
  optional<NodeId> mSourceNode{};  ///< Source node.
  optional<String> mSourceName{};  ///< Source name.
  LocalizedText mMessage{};  ///< Message.
  optional<TraceContextDataType> mTraceContext{};  ///< Trace context.
  optional<Array<NameValuePair>> mAdditionalData{};  ///< Additional data.
};

template<>
inline string_view get_typename<LogRecord>()
{
  return LogRecord::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_LOG_RECORD_H
