// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_APPLICATION_DESCRIPTION_H
#define UA_DATA_TYPE_APPLICATION_DESCRIPTION_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_string.h"
#include "ua_localized_text.h"
#include "ua_application_type.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA ApplicationDescription structured data type.
/// @ingroup ua_data_types
class ApplicationDescription : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"ApplicationDescription"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::ApplicationDescription};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::ApplicationDescription_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::ApplicationDescription_Encoding_DefaultXml};

  /// Constructs a `ApplicationDescription` with all fields value-initialised.
  ApplicationDescription() = default;
  /// Defaulted copy: `ApplicationDescription` is a value type (memberwise copy).
  /// @param other The value to copy from.
  ApplicationDescription(const ApplicationDescription& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  ApplicationDescription(ApplicationDescription&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  ApplicationDescription& operator=(const ApplicationDescription& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  ApplicationDescription& operator=(ApplicationDescription&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~ApplicationDescription() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const ApplicationDescription& obj) const = default;

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

  /// Accesses the `ApplicationUri` field.
  /// @return A mutable reference to the `ApplicationUri` field.
  String& application_uri();
  /// @return A const reference to the `ApplicationUri` field.
  const String& application_uri() const;

  /// Accesses the `ProductUri` field.
  /// @return A mutable reference to the `ProductUri` field.
  String& product_uri();
  /// @return A const reference to the `ProductUri` field.
  const String& product_uri() const;

  /// Accesses the `ApplicationName` field.
  /// @return A mutable reference to the `ApplicationName` field.
  LocalizedText& application_name();
  /// @return A const reference to the `ApplicationName` field.
  const LocalizedText& application_name() const;

  /// Accesses the `ApplicationType` field.
  /// @return A mutable reference to the `ApplicationType` field.
  ApplicationType& application_type();
  /// @return A const reference to the `ApplicationType` field.
  const ApplicationType& application_type() const;

  /// Accesses the `GatewayServerUri` field.
  /// @return A mutable reference to the `GatewayServerUri` field.
  String& gateway_server_uri();
  /// @return A const reference to the `GatewayServerUri` field.
  const String& gateway_server_uri() const;

  /// Accesses the `DiscoveryProfileUri` field.
  /// @return A mutable reference to the `DiscoveryProfileUri` field.
  String& discovery_profile_uri();
  /// @return A const reference to the `DiscoveryProfileUri` field.
  const String& discovery_profile_uri() const;

  /// Accesses the `DiscoveryUrls` field.
  /// @return A mutable reference to the `DiscoveryUrls` field.
  Array<String>& discovery_urls();
  /// @return A const reference to the `DiscoveryUrls` field.
  const Array<String>& discovery_urls() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  String mApplicationUri{};  ///< Application URI.
  String mProductUri{};  ///< Product URI.
  LocalizedText mApplicationName{};  ///< Application name.
  ApplicationType mApplicationType{};  ///< Application type.
  String mGatewayServerUri{};  ///< Gateway server URI.
  String mDiscoveryProfileUri{};  ///< Discovery profile URI.
  Array<String> mDiscoveryUrls{};  ///< Discovery urls.
};

template<>
inline string_view get_typename<ApplicationDescription>()
{
  return ApplicationDescription::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_APPLICATION_DESCRIPTION_H
