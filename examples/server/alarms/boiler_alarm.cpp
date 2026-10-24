// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "boiler_alarm.h"

#include "ua_access_level_type.h"
#include "ua_alarm_condition_logic.h"
#include "ua_argument.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_call_method_result.h"
#include "ua_condition_instance.h"
#include "ua_conditions.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_exceptions.h"
#include "ua_method_adapter.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_read_value_id.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_server.h"
#include "ua_utilities.h"
#include "ua_value_rank.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"
#include "ua_well_known_role_permissions.h"

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace examples::boiler
{
namespace
{
// Change these for your model.
constexpr double initialTemperature = 20.0;
constexpr std::uint32_t conditionIdentifier = 6001;

/// Adds the InputArguments Property so a client can discover what `Heat` expects.
///
/// The Call service reads this to check the argument list before the handler runs. A Method without
/// it still works, but nothing can introspect it.
void add_heat_arguments(ua::AddressSpace& addressSpace, const ua::NodeId& methodId,
  std::uint16_t namespaceIndex, const ua::NodeId& propertyId)
{
  ua::VariableAccessor property =
    addressSpace.create_node_sync(propertyId, ua::NodeClass::Variable).as<ua::VariableAccessor>().value();
  property.set_browse_name(ua::QualifiedName{0, "InputArguments"});
  property.set_display_name(ua::LocalizedText{"", "InputArguments"});
  property.set_data_type(ua::NodeId{ua::DataTypeId::Argument});
  property.set_value_rank(ua::ValueRank{1});
  property.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::PropertyType});

  ua::Argument delta;
  delta.name() = std::string{"Delta"};
  delta.description() = ua::LocalizedText{"", "Degrees to add to the current temperature"};
  delta.data_type() = ua::NodeId{ua::DataTypeId::Double};
  delta.value_rank() = -1;  // -1 is a scalar

  ua::Array<ua::RefStructure<ua::Structure>> arguments;
  arguments.resize(1);
  arguments[0] = ua::RefStructure<ua::Structure>{std::make_unique<ua::Argument>(std::move(delta))};
  ua::DataValue value;
  value.value() = ua::Variant{std::move(arguments)};
  property.write_value_sync(std::move(value));

  addressSpace.find_node_sync(methodId).add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasProperty}, propertyId);
  (void)namespaceIndex;
}

}  // namespace

std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  const std::vector<ua::RolePermissionType> operatorMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Operator,
      ua::PermissionType{ua::PermissionType::Bit::Browse,
        ua::PermissionType::Bit::Read,
        ua::PermissionType::Bit::Write,
        ua::PermissionType::Bit::Call,
        ua::PermissionType::Bit::ReceiveEvents})};
  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, operatorMay, {}));
}

ua::NodeId add_boiler(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const ua::NodeId boilerId{namespaceIndex, "Boiler"};
  ua::NodeAccessor boiler = addressSpace.create_node_sync(boilerId, ua::NodeClass::Object);
  boiler.set_browse_name(ua::QualifiedName{namespaceIndex, "Boiler"});
  boiler.set_display_name(ua::LocalizedText{"", "Boiler"});
  boiler.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::BaseObjectType});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, boilerId);

  const ua::NodeId temperatureId{namespaceIndex, "Boiler.Temperature"};
  ua::VariableAccessor temperature =
    addressSpace.create_node_sync(temperatureId, ua::NodeClass::Variable).as<ua::VariableAccessor>().value();
  temperature.set_browse_name(ua::QualifiedName{namespaceIndex, "Temperature"});
  temperature.set_display_name(ua::LocalizedText{"", "Temperature"});
  temperature.set_data_type(ua::NodeId{ua::DataTypeId::Double});
  temperature.set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead});
  temperature.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
  boiler.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, temperatureId);
  temperature.write_value_sync(initialTemperature);

  const ua::NodeId heatId{namespaceIndex, "Boiler.Heat"};
  ua::NodeAccessor heatNode = addressSpace.create_node_sync(heatId, ua::NodeClass::Method);
  ua::MethodAccessor heat = heatNode.as<ua::MethodAccessor>().value();
  heat.set_browse_name(ua::QualifiedName{namespaceIndex, "Heat"});
  heat.set_display_name(ua::LocalizedText{"", "Heat"});
  heat.set_executable(true);
  boiler.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, heatId);
  add_heat_arguments(addressSpace, heatId, namespaceIndex, ua::NodeId{namespaceIndex, "Boiler.Heat.In"});

  return temperatureId;
}

void add_high_temperature_alarm(ua::server::Server& server, ua::AddressSpace& addressSpace,
  std::uint16_t namespaceIndex, const ua::NodeId& source)
{
  // A condition is created once and lives in the address space. It is not raised and forgotten like
  // an event: activating and deactivating it changes the state clients can query and are told about.
  std::shared_ptr<ua::ConditionInstance> alarm =
    server.conditions().create_condition_sync(ua::NodeId{namespaceIndex, conditionIdentifier},
      source,
      ua::String{std::string{"Boiler.Temperature"}},
      std::make_unique<ua::AlarmConditionLogic>(),
      ua::NodeId{ua::ObjectTypeId::AlarmConditionType});
  alarm->enable_sync();

  ua::VariableAccessor temperature = addressSpace.find_node_sync(source).as<ua::VariableAccessor>().value();
  const ua::NodeId heatId{namespaceIndex, "Boiler.Heat"};

  // The handler is where the application decides the alarm's state. The SDK owns the condition's
  // bookkeeping - retain, acknowledged state, event generation - and never guesses the process
  // meaning: nothing but this code knows that "too hot" is what matters here.
  //
  // The handler holds a WEAK pointer to the condition, not a shared one. The handler lives on a node
  // the address space owns, and the condition is owned by the server: an owning capture here closes
  // a cycle through the server, and shutdown then waits for a reference that shutdown itself has to
  // drop. The symptom is a clean run that never exits.
  using HeatArguments = std::tuple<double>;
  auto handler = [temperature, weakAlarm = std::weak_ptr<ua::ConditionInstance>{alarm}](const ua::NodeId&,
                   const HeatArguments& arguments,
                   std::shared_ptr<const ua::MethodCallContext>,
                   ua::CallMethodResult result,
                   ua::CallMethodCompleteCallback complete) mutable
  {
    // A method handler runs on a thread of the server's executor, and work it waits for may be queued to
    // that same executor - so blocking here would occupy the very thread that work needs. The synchronous
    // forms refuse on that thread (Bad_WouldBlock); the handler reads, writes and changes the condition
    // through the asynchronous forms and answers from the last completion, once.
    ua::ReadValueId nodeToRead;
    nodeToRead.node_id() = temperature.get_node_id();
    nodeToRead.attribute_id() = ua::utils::to_underlying(ua::AttributeId::Value);
    const double added = std::get<0>(arguments);
    temperature.read_value_async(0.0,
      false,
      nodeToRead,
      nullptr,
      [temperature, weakAlarm, added, result = std::move(result), complete = std::move(complete)](
        ua::DataValueResult current) mutable
      {
        const auto number = current.is_good()
                              ? current.value().value().to<double>()
                              : ua::Result<double>{current.status_code(), current.shared_detail()};
        if (!number)
        {
          return complete(ua::CallResult{number.status_code(), number.shared_detail()});
        }
        const double heated = number.value() + added;
        temperature.write_value_async(ua::DataValue{ua::Variant{heated}},
          [heated, weakAlarm, result = std::move(result), complete = std::move(complete)](
            ua::VoidResult written) mutable
          {
            if (written.is_bad())
            {
              return complete(ua::CallResult{written.status_code(), written.shared_detail()});
            }
            const std::shared_ptr<ua::ConditionInstance> condition = weakAlarm.lock();
            if (!condition)
            {
              return complete(ua::CallResult{std::move(result)});
            }
            // The method answers when the transition has landed, not before it.
            auto answerWhenTransitioned = [result = std::move(result), complete = std::move(complete)](
                                            ua::VoidResult) mutable
            {
              complete(ua::CallResult{std::move(result)});
            };
            if (heated >= highThreshold)
            {
              condition->activate_async(highSeverity, std::move(answerWhenTransitioned));
            }
            else
            {
              condition->deactivate_async(std::move(answerWhenTransitioned));
            }
          });
      });
  };

  auto* callSource = addressSpace.find_node_sync(heatId)->method_call_source();
  if (callSource == nullptr)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadNotSupported}};
  }
  const ua::StatusCode installed = callSource->set_call_handler(ua::MethodAdapter<HeatArguments>{handler});
  if (!installed.is_good())
  {
    throw ua::UaException{installed};
  }
}

}  // namespace examples::boiler
