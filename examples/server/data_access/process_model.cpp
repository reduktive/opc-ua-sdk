// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "process_model.h"

#include "ua_address_space.h"

#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_analog_unit_range.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_property.h"
#include "ua_eu_information.h"
#include "ua_instantiation_options.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_range.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_two_state_discrete.h"
#include "ua_value_rank.h"
#include "ua_variant.h"
#include "ua_well_known_role_permissions.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace examples::process
{
namespace
{
// Change these for your model.
constexpr double initialTemperature = 82.5;
// UNECE unit codes, the vocabulary OPC UA Part 8 points at for EngineeringUnits. 4408524 is degrees
// Celsius; a deployment looks its own units up rather than inventing an identifier.
constexpr std::int32_t celsiusUnitId = 4408524;
constexpr std::string_view unitNamespaceUri = "http://www.opcfoundation.org/UA/units/un/cefact";
constexpr std::string_view unitDescription = "degree Celsius";
constexpr bool initialPumpRunning = true;

/// Registers the namespace these measurements live in.
/// Writes a Property's value.
///
/// A Property is a Variable, so what it holds is a DataValue: the value together with the status and
/// timestamps a client reads alongside it. Only the value part matters here.
void write_property(ua::Property property, ua::Variant value)
{
  ua::DataValue wrapped;
  wrapped.value() = std::move(value);
  property.write_value_sync(std::move(wrapped));
}

}  // namespace

std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  const std::vector<ua::RolePermissionType> observerMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Observer,
      ua::PermissionType{
        ua::PermissionType::Bit::Browse, ua::PermissionType::Bit::Read, ua::PermissionType::Bit::Write})};

  const ua::AccessRestrictionType secureSessionOnly{ua::AccessRestrictionType::Bit::SigningRequired,
    ua::AccessRestrictionType::Bit::EncryptionRequired,
    ua::AccessRestrictionType::Bit::SessionRequired,
    ua::AccessRestrictionType::Bit::ApplyRestrictionsToBrowse};

  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, observerMay, secureSessionOnly));
}

/// Adds the `Boiler` folder the two measurements hang from.
ua::NodeId add_boiler_folder(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const ua::NodeId boilerId{namespaceIndex, "Boiler"};
  ua::NodeAccessor boiler = addressSpace.create_node_sync(boilerId, ua::NodeClass::Object);
  boiler.set_browse_name(ua::QualifiedName{namespaceIndex, "Boiler"});
  boiler.set_display_name(ua::LocalizedText{"", "Boiler"});
  boiler.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::FolderType});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, boilerId);
  return boilerId;
}

/// Publishes `Temperature` as an AnalogUnitRangeType, with the range and units that give it meaning.
///
/// AnalogUnitRangeType rather than the plainer AnalogItemType, because it is the type that means
/// what this example is about: AnalogItemType mandates only EURange and leaves EngineeringUnits
/// Optional, and instantiation materialises exactly what a type mandates. Choosing the weaker type
/// and then reaching for the units Property gets BadNodeIdUnknown - the Property was never created.
///
/// The generated type instantiates the whole thing: the Variable and every Property the type
/// mandates, already referenced and typed. By hand it means getting each Property's own DataType,
/// ValueRank and reference right, and a client that finds one missing treats the node as ordinary.
///
/// Instantiation also registers EURange and EngineeringUnits with the namespace's semantic-change
/// source, so a later edit of the range tells subscribed clients their cached copy is stale.
void publish_temperature(
  ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex, const ua::NodeId& parent)
{
  ua::InstantiationOptions options;
  options.targetNamespaceIndex = namespaceIndex;
  const ua::VariableInstantiationAttributes attributes{.dataType = ua::NodeId{ua::DataTypeId::Double},
    .valueRank = ua::ValueRank::scalar,
    .accessLevel =
      ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::CurrentWrite}};

  ua::AnalogUnitRange temperature = ua::AnalogUnitRange::create_sync(
    addressSpace, parent, ua::QualifiedName{namespaceIndex, "Temperature"}, options, attributes);

  ua::Range range;
  range.low() = rangeLow;
  range.high() = rangeHigh;
  write_property(temperature.eu_range_property_sync(), ua::Variant{range});

  ua::EUInformation units;
  units.namespace_uri() = ua::String{std::string{unitNamespaceUri}};
  units.unit_id() = celsiusUnitId;
  units.display_name() = ua::LocalizedText{"", std::string{unitSymbol}};
  units.description() = ua::LocalizedText{"", std::string{unitDescription}};
  write_property(temperature.engineering_units_property_sync(), ua::Variant{std::move(units)});

  addressSpace.find_node_sync(temperature.node_id())
    .as<ua::VariableAccessor>()
    .value()
    .write_value_sync(initialTemperature);

  // The handle OWNS everything it just created and removes it when destroyed. Releasing hands the
  // nodes to the address space, which is what a server wants; forget this and the model disappears
  // at the end of this function.
  temperature.release();
}

/// Publishes `Pump` as a TwoStateDiscreteType, whose two states carry the names an operator reads.
///
/// A Boolean on its own says `true`. The type's two Mandatory Properties say what `true` means here,
/// so a display can label the state without the meaning being agreed out of band.
void publish_pump(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex, const ua::NodeId& parent)
{
  ua::InstantiationOptions options;
  options.targetNamespaceIndex = namespaceIndex;
  const ua::VariableInstantiationAttributes attributes{.dataType = ua::NodeId{ua::DataTypeId::Boolean},
    .valueRank = ua::ValueRank::scalar,
    .accessLevel =
      ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::CurrentWrite}};

  ua::TwoStateDiscrete pump = ua::TwoStateDiscrete::create_sync(
    addressSpace, parent, ua::QualifiedName{namespaceIndex, "Pump"}, options, attributes);

  write_property(
    pump.true_state_property_sync(), ua::Variant{ua::LocalizedText{"", std::string{pumpTrueState}}});
  write_property(
    pump.false_state_property_sync(), ua::Variant{ua::LocalizedText{"", std::string{pumpFalseState}}});

  addressSpace.find_node_sync(pump.node_id())
    .as<ua::VariableAccessor>()
    .value()
    .write_value_sync(initialPumpRunning);

  pump.release();
}

void add_process_model(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const ua::NodeId boiler = add_boiler_folder(addressSpace, namespaceIndex);
  publish_temperature(addressSpace, namespaceIndex, boiler);
  publish_pump(addressSpace, namespaceIndex, boiler);
}

}  // namespace examples::process
