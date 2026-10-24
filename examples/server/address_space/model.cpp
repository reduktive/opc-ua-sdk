// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "model.h"

#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_add_method.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_utilities.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"
#include "ua_well_known_role_permissions.h"

#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace examples::plant
{
namespace
{
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:plant";
constexpr double initialTemperature = 82.5;
constexpr double initialSetpoint = 80.0;

/// Creates a Variable, gives it the attributes a client needs, and attaches it to @p parent.
///
/// A Variable is usable only once it has all four: a BrowseName to be found by, a data type, an
/// access level saying which operations are permitted, and a type definition.
ua::VariableAccessor add_variable(ua::AddressSpace& addressSpace, const ua::NodeId& parent,
  std::uint16_t namespaceIndex, std::string_view name, const ua::AccessLevelType& accessLevel)
{
  const ua::NodeId id{namespaceIndex, std::string{name}};
  ua::VariableAccessor variable =
    addressSpace.create_node_sync(id, ua::NodeClass::Variable).as<ua::VariableAccessor>().value();
  variable.set_browse_name(ua::QualifiedName{namespaceIndex, std::string{name}});
  variable.set_display_name(ua::LocalizedText{"", std::string{name}});
  variable.set_data_type(ua::NodeId{ua::DataTypeId::Double});
  variable.set_access_level(accessLevel);
  variable.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
  addressSpace.find_node_sync(parent).add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, id);
  return variable;
}

}  // namespace

std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  // The namespace default is inherited by every node that carries no permissions of its own.
  // Granting nothing means exactly that: a Session could not even browse these nodes.
  const std::vector<ua::RolePermissionType> observerMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Observer,
      ua::PermissionType{ua::PermissionType::Bit::Browse,
        ua::PermissionType::Bit::Read,
        ua::PermissionType::Bit::Write,
        ua::PermissionType::Bit::Call})};

  const ua::AccessRestrictionType secureSessionOnly{ua::AccessRestrictionType::Bit::SigningRequired,
    ua::AccessRestrictionType::Bit::EncryptionRequired,
    ua::AccessRestrictionType::Bit::SessionRequired,
    ua::AccessRestrictionType::Bit::ApplyRestrictionsToBrowse};

  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, observerMay, secureSessionOnly));
}

void add_plant(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  // A folder is an Object whose type definition is FolderType. Organizes is the loose "is listed
  // under" relationship; HasComponent below is the tighter "is part of".
  const ua::NodeId plantId{namespaceIndex, "Plant"};
  ua::NodeAccessor plant = addressSpace.create_node_sync(plantId, ua::NodeClass::Object);
  plant.set_browse_name(ua::QualifiedName{namespaceIndex, "Plant"});
  plant.set_display_name(ua::LocalizedText{"", "Plant"});
  plant.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::FolderType});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, plantId);

  const ua::NodeId boilerId{namespaceIndex, "Boiler"};
  ua::NodeAccessor boiler = addressSpace.create_node_sync(boilerId, ua::NodeClass::Object);
  boiler.set_browse_name(ua::QualifiedName{namespaceIndex, "Boiler"});
  boiler.set_display_name(ua::LocalizedText{"", "Boiler"});
  boiler.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::BaseObjectType});
  plant.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, boilerId);

  const ua::AccessLevelType readOnly{ua::AccessLevelType::Bit::CurrentRead};
  const ua::AccessLevelType readWrite{
    ua::AccessLevelType::Bit::CurrentRead, ua::AccessLevelType::Bit::CurrentWrite};
  add_variable(addressSpace, boilerId, namespaceIndex, "Temperature", readOnly)
    .write_value_sync(initialTemperature);
  ua::VariableAccessor setpoint = add_variable(addressSpace, boilerId, namespaceIndex, "Setpoint", readWrite);
  setpoint.write_value_sync(initialSetpoint);

  // A Method is a node too, with its signature in InputArguments and OutputArguments Properties.
  // add_method_sync creates the Method, its HasComponent reference and both Properties, and installs
  // the handler, from one description, so the signature a client reads and the decoding cannot
  // disagree.
  //
  // The handler runs on a thread of the server's executor, where a *_sync call is refused, so it has
  // the asynchronous form: it reads and writes the Setpoint with the asynchronous calls and completes
  // the call through `done`, exactly once, from whichever step ends it.
  ua::add_method_sync(addressSpace,
    boilerId,
    ua::QualifiedName{namespaceIndex, "Scale"},
    ua::inputs(ua::arg<double>("Factor", "Multiplies the current Setpoint")),
    ua::outputs(ua::arg<double>("Setpoint", "The Setpoint after scaling")),
    [setpoint](const ua::MethodCall&, double factor, ua::MethodResultCallback<double> done) mutable
    {
      if (factor <= 0.0)
      {
        return done(ua::reject_argument(0, ua::Status::BadOutOfRange));
      }
      ua::ReadValueId nodeToRead;
      nodeToRead.node_id() = setpoint.get_node_id();
      nodeToRead.attribute_id() = ua::utils::to_underlying(ua::AttributeId::Value);
      setpoint.read_value_async(0.0,
        false,
        nodeToRead,
        nullptr,
        [setpoint, factor, done](ua::DataValueResult current) mutable
        {
          if (!current)
          {
            // Only a Good Setpoint is scaled. The Method has an output, so it fails with a Bad status: an
            // Uncertain read is answered Bad_InvalidState, with the read's code as the cause.
            return done(
              current.is_bad()
                ? current.status_code()
                : ua::StatusCode{ua::Status::BadInvalidState,
                    ua::ErrorDetail::build("SetpointUncertain", "The Setpoint was read Uncertain", "Scale")
                      .cause(current.status_code())});
          }
          const auto number = current.value().value().to<double>();
          if (!number)
          {
            return done(number);
          }
          const double scaled = number.value() * factor;
          setpoint.write_value_async(ua::DataValue{ua::Variant{scaled}},
            [scaled, done](ua::VoidResult written)
            {
              if (written.is_bad())
              {
                return done(written);
              }
              done(scaled);
            });
        });
    },
    {.nodeId = ua::NodeId{namespaceIndex, "Scale"}});
}

}  // namespace examples::plant
