// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_QUANTITY_DIMENSION_H
#define UA_DATA_TYPE_QUANTITY_DIMENSION_H

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

/// OPC UA QuantityDimension structured data type.
/// @ingroup ua_data_types
class QuantityDimension : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"QuantityDimension"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::QuantityDimension};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::QuantityDimension_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::QuantityDimension_Encoding_DefaultXml};

  /// Constructs a `QuantityDimension` with all fields value-initialised.
  QuantityDimension() = default;
  /// Defaulted copy: `QuantityDimension` is a value type (memberwise copy).
  /// @param other The value to copy from.
  QuantityDimension(const QuantityDimension& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  QuantityDimension(QuantityDimension&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  QuantityDimension& operator=(const QuantityDimension& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  QuantityDimension& operator=(QuantityDimension&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~QuantityDimension() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const QuantityDimension& obj) const = default;

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

  /// Accesses the `MassExponent` field.
  /// @return A mutable reference to the `MassExponent` field.
  int8_t& mass_exponent();
  /// @return A const reference to the `MassExponent` field.
  const int8_t& mass_exponent() const;

  /// Accesses the `LengthExponent` field.
  /// @return A mutable reference to the `LengthExponent` field.
  int8_t& length_exponent();
  /// @return A const reference to the `LengthExponent` field.
  const int8_t& length_exponent() const;

  /// Accesses the `TimeExponent` field.
  /// @return A mutable reference to the `TimeExponent` field.
  int8_t& time_exponent();
  /// @return A const reference to the `TimeExponent` field.
  const int8_t& time_exponent() const;

  /// Accesses the `ElectricCurrentExponent` field.
  /// @return A mutable reference to the `ElectricCurrentExponent` field.
  int8_t& electric_current_exponent();
  /// @return A const reference to the `ElectricCurrentExponent` field.
  const int8_t& electric_current_exponent() const;

  /// Accesses the `AmountOfSubstanceExponent` field.
  /// @return A mutable reference to the `AmountOfSubstanceExponent` field.
  int8_t& amount_of_substance_exponent();
  /// @return A const reference to the `AmountOfSubstanceExponent` field.
  const int8_t& amount_of_substance_exponent() const;

  /// Accesses the `LuminousIntensityExponent` field.
  /// @return A mutable reference to the `LuminousIntensityExponent` field.
  int8_t& luminous_intensity_exponent();
  /// @return A const reference to the `LuminousIntensityExponent` field.
  const int8_t& luminous_intensity_exponent() const;

  /// Accesses the `AbsoluteTemperatureExponent` field.
  /// @return A mutable reference to the `AbsoluteTemperatureExponent` field.
  int8_t& absolute_temperature_exponent();
  /// @return A const reference to the `AbsoluteTemperatureExponent` field.
  const int8_t& absolute_temperature_exponent() const;

  /// Accesses the `DimensionlessExponent` field.
  /// @return A mutable reference to the `DimensionlessExponent` field.
  int8_t& dimensionless_exponent();
  /// @return A const reference to the `DimensionlessExponent` field.
  const int8_t& dimensionless_exponent() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  int8_t mMassExponent{};  ///< Mass exponent.
  int8_t mLengthExponent{};  ///< Length exponent.
  int8_t mTimeExponent{};  ///< Time exponent.
  int8_t mElectricCurrentExponent{};  ///< Electric current exponent.
  int8_t mAmountOfSubstanceExponent{};  ///< Amount of substance exponent.
  int8_t mLuminousIntensityExponent{};  ///< Luminous intensity exponent.
  int8_t mAbsoluteTemperatureExponent{};  ///< Absolute temperature exponent.
  int8_t mDimensionlessExponent{};  ///< Dimensionless exponent.
};

template<>
inline string_view get_typename<QuantityDimension>()
{
  return QuantityDimension::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_QUANTITY_DIMENSION_H
