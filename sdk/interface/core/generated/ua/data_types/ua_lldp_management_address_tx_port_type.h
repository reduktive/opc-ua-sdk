// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_LLDP_MANAGEMENT_ADDRESS_TX_PORT_TYPE_H
#define UA_DATA_TYPE_LLDP_MANAGEMENT_ADDRESS_TX_PORT_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_string.h"
#include "ua_man_addr_if_subtype.h"

namespace ua
{

class StructureFactory;

/// OPC UA LldpManagementAddressTxPortType structured data type.
/// @ingroup ua_data_types
class LldpManagementAddressTxPortType : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"LldpManagementAddressTxPortType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::LldpManagementAddressTxPortType};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{
    ObjectId::LldpManagementAddressTxPortType_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::LldpManagementAddressTxPortType_Encoding_DefaultXml};

  /// Constructs a `LldpManagementAddressTxPortType` with all fields value-initialised.
  LldpManagementAddressTxPortType() = default;
  /// Defaulted copy: `LldpManagementAddressTxPortType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  LldpManagementAddressTxPortType(const LldpManagementAddressTxPortType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  LldpManagementAddressTxPortType(LldpManagementAddressTxPortType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  LldpManagementAddressTxPortType& operator=(const LldpManagementAddressTxPortType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  LldpManagementAddressTxPortType& operator=(LldpManagementAddressTxPortType&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~LldpManagementAddressTxPortType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const LldpManagementAddressTxPortType& obj) const = default;

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

  /// Accesses the `AddressSubtype` field.
  /// @return A mutable reference to the `AddressSubtype` field.
  uint32_t& address_subtype();
  /// @return A const reference to the `AddressSubtype` field.
  const uint32_t& address_subtype() const;

  /// Accesses the `ManAddress` field.
  /// @return A mutable reference to the `ManAddress` field.
  String& man_address();
  /// @return A const reference to the `ManAddress` field.
  const String& man_address() const;

  /// Accesses the `TxEnable` field.
  /// @return A mutable reference to the `TxEnable` field.
  bool& tx_enable();
  /// @return A const reference to the `TxEnable` field.
  const bool& tx_enable() const;

  /// Accesses the `AddrLen` field.
  /// @return A mutable reference to the `AddrLen` field.
  uint32_t& addr_len();
  /// @return A const reference to the `AddrLen` field.
  const uint32_t& addr_len() const;

  /// Accesses the `IfSubtype` field.
  /// @return A mutable reference to the `IfSubtype` field.
  ManAddrIfSubtype& if_subtype();
  /// @return A const reference to the `IfSubtype` field.
  const ManAddrIfSubtype& if_subtype() const;

  /// Accesses the `IfId` field.
  /// @return A mutable reference to the `IfId` field.
  uint32_t& if_id();
  /// @return A const reference to the `IfId` field.
  const uint32_t& if_id() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  uint32_t mAddressSubtype{};  ///< Address subtype.
  String mManAddress{};  ///< Man address.
  bool mTxEnable{};  ///< Tx enable.
  uint32_t mAddrLen{};  ///< Addr len.
  ManAddrIfSubtype mIfSubtype{};  ///< If subtype.
  uint32_t mIfId{};  ///< If ID.
};

template<>
inline string_view get_typename<LldpManagementAddressTxPortType>()
{
  return LldpManagementAddressTxPortType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_LLDP_MANAGEMENT_ADDRESS_TX_PORT_TYPE_H
