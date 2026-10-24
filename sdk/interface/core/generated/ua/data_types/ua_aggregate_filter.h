// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_AGGREGATE_FILTER_H
#define UA_DATA_TYPE_AGGREGATE_FILTER_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_monitoring_filter.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_utc_time.h"
#include "ua_node_id.h"
#include "ua_duration.h"
#include "ua_aggregate_configuration.h"

namespace ua
{

class StructureFactory;

/// OPC UA AggregateFilter structured data type.
/// @ingroup ua_data_types
class AggregateFilter : public MonitoringFilter
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"AggregateFilter"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::AggregateFilter};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::AggregateFilter_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::AggregateFilter_Encoding_DefaultXml};

  /// Constructs a `AggregateFilter` with all fields value-initialised.
  AggregateFilter() = default;
  /// Defaulted copy: `AggregateFilter` is a value type (memberwise copy).
  /// @param other The value to copy from.
  AggregateFilter(const AggregateFilter& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  AggregateFilter(AggregateFilter&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  AggregateFilter& operator=(const AggregateFilter& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  AggregateFilter& operator=(AggregateFilter&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~AggregateFilter() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const AggregateFilter& obj) const = default;

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

  /// Accesses the `StartTime` field.
  /// @return A mutable reference to the `StartTime` field.
  UtcTime& start_time();
  /// @return A const reference to the `StartTime` field.
  const UtcTime& start_time() const;

  /// Accesses the `AggregateType` field.
  /// @return A mutable reference to the `AggregateType` field.
  NodeId& aggregate_type();
  /// @return A const reference to the `AggregateType` field.
  const NodeId& aggregate_type() const;

  /// Accesses the `ProcessingInterval` field.
  /// @return A mutable reference to the `ProcessingInterval` field.
  Duration& processing_interval();
  /// @return A const reference to the `ProcessingInterval` field.
  const Duration& processing_interval() const;

  /// Accesses the `AggregateConfiguration` field.
  /// @return A mutable reference to the `AggregateConfiguration` field.
  AggregateConfiguration& aggregate_configuration();
  /// @return A const reference to the `AggregateConfiguration` field.
  const AggregateConfiguration& aggregate_configuration() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  UtcTime mStartTime{};  ///< Start time.
  NodeId mAggregateType{};  ///< Aggregate type.
  Duration mProcessingInterval{};  ///< Processing interval.
  AggregateConfiguration mAggregateConfiguration{};  ///< Aggregate configuration.
};

template<>
inline string_view get_typename<AggregateFilter>()
{
  return AggregateFilter::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_AGGREGATE_FILTER_H
