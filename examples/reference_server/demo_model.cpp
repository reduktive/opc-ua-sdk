// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "demo_model.h"

#include "ua_access_restriction_type.h"
#include "ua_base_data_variable.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_numeric_range_parser.h"
#include "ua_object_id.h"
#include "ua_permission_type.h"
#include "ua_reference_demo_demo.h"
#include "ua_reference_demo_method_id.h"
#include "ua_reference_demo_object_id.h"
#include "ua_role_configuration.h"
#include "ua_server.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_value_source.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

namespace reduktive::reference
{
namespace
{
namespace model = ua::reference_demo;

// Builds the namespace-level access restriction used by the demonstration model. Requiring a
// Session plus signed and encrypted messages prevents even browsing the model over an unsecured
// channel; ApplyRestrictionsToBrowse makes that browse restriction explicit.
ua::AccessRestrictionType secure_session_only()
{
  using Bit = ua::AccessRestrictionType::Bit;
  return ua::AccessRestrictionType{
    Bit::SigningRequired, Bit::EncryptionRequired, Bit::SessionRequired, Bit::ApplyRestrictionsToBrowse};
}

// Converts the supplied permission bits into the role-permission list expected by address-space
// nodes. The reference application's anonymous authenticator maps its user to the well-known
// Observer role, so this helper expresses the namespace policy without repeating it on every node.
std::vector<ua::RolePermissionType> observer_permissions(ua::PermissionType permissions)
{
  return {
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Observer, std::move(permissions))};
}

// Logs an application-level rejection at the boundary where the server has handled it. Both the
// StatusCode and its ErrorDetail are retained in structured log fields so the contextual cause is
// not lost after the protocol response has been completed.
void log_rejection(ua::Logger& logger, std::string_view operation, const ua::StatusCode& failure)
{
  const std::string statusText = ua::to_string(failure);
  if (const auto& detail = failure.shared_detail())
  {
    const std::string detailText = ua::to_string(*detail);
    logger.warning({{"operation", operation}, {"status", statusText}, {"error_detail", detailText}},
      "Reference server operation rejected");
    return;
  }
  logger.warning({{"operation", operation}, {"status", statusText}}, "Reference server operation rejected");
}

// Combines the namespace index assigned at runtime with the stable numeric identifier emitted for
// the Demo instance by the type generator. Clients resolve the namespace URI independently, so no
// code relies on a hard-coded namespace index.
ua::NodeId demo_node_id(std::uint16_t namespaceIndex)
{
  return ua::NodeId{namespaceIndex, static_cast<std::uint32_t>(model::ObjectId::Demo)};
}

}  // namespace

// Connects the static information model to live application behaviour. The XML file remains the
// source of truth for nodes and signatures; this function supplies only runtime policy and value /
// Method handlers through the generated typed API.
ua::VoidResult try_configure_demo_model(
  ua::server::Server& server, const std::filesystem::path& modelPath, ua::Logger applicationLogger) noexcept
{
  try
  {
    // Register the model URI before import so the XML namespace is mapped to a runtime index. Every
    // imported node has no RolePermissions of its own and therefore inherits these Observer defaults.
    // NodeClass, AccessLevel, Executable, and WriteMask still decide whether each granted operation
    // applies to a particular node. The namespace also requires a secure Session for every node.
    auto addressSpace = server.address_space();
    auto demoNamespace = addressSpace.create_namespace(std::string{demoNamespaceUri},
      observer_permissions(ua::PermissionType{ua::PermissionType::Bit::Browse,
        ua::PermissionType::Bit::Read,
        ua::PermissionType::Bit::Write,
        ua::PermissionType::Bit::Call}),
      secure_session_only());
    auto namespaceResult = addressSpace.try_add_namespace_sync(std::move(demoNamespace));
    if (!namespaceResult.is_good())
    {
      return namespaceResult.status_code();
    }
    const std::uint16_t namespaceIndex = namespaceResult.value();

    // Open and import the caller-selected NodeSet. Generation is intentionally absent here and from
    // CMake: the reference executable consumes the external XML and checked-in generated helpers.
    ua::FileStream modelStream{modelPath};
    const ua::StatusCode opened = modelStream.open_for_read();
    if (!opened.is_good())
    {
      return opened;
    }
    auto importResult = server.try_import_nodeset_sync(modelStream);
    if (!importResult.is_good())
    {
      return importResult.status_code();
    }

    // Attach the generated Demo wrapper to the canonical instance imported from the NodeSet. This
    // validates the expected type and exposes typed accessors for its children and Method signature.
    auto demoResult = model::Demo::try_attach_sync(addressSpace, demo_node_id(namespaceIndex));
    if (!demoResult.is_good())
    {
      return demoResult.status_code();
    }
    auto demo = std::move(demoResult).value();

    // Resolve UptimeSeconds through its generated typed accessor and supply a read handler whose
    // value is derived from steady time, making it immune to wall-clock adjustments.
    auto uptimeResult = demo.try_uptime_seconds_sync();
    if (!uptimeResult.is_good())
    {
      return uptimeResult.status_code();
    }
    auto uptime = std::move(uptimeResult).value();

    const auto started = std::chrono::steady_clock::now();
    auto uptimeHandlerResult = uptime.try_set_value_source_sync(ua::make_value_source(
      [started](const ua::ValueSource::ReadContext& /*context*/,
        const ua::Node& /*node*/,
        const ua::ReadValueId& read,
        std::function<void(ua::DataValueResult)>
          complete)
      {
        // Clamp the elapsed count to UInt32 because that is the data type declared by the NodeSet.
        // Both timestamps describe when this handler produced the live value.
        const auto elapsed =
          std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - started);
        const auto seconds = std::min<std::uint64_t>(
          static_cast<std::uint64_t>(elapsed.count()), std::numeric_limits<std::uint32_t>::max());
        ua::DataValue value;
        value.value() = static_cast<std::uint32_t>(seconds);
        value.server_timestamp() = ua::DateTime::now();
        value.source_timestamp() = value.server_timestamp();
        ua::index_range_utils::apply_to_value(value, read.index_range());
        complete(std::move(value));
      }));
    if (!uptimeHandlerResult.is_good())
    {
      return uptimeHandlerResult.status_code();
    }

    // Resolve Setpoint through its generated typed accessor. It inherits the namespace permissions;
    // its modelled AccessLevel limits the otherwise available Write permission to this Variable.
    auto setpointResult = demo.try_setpoint_sync();
    if (!setpointResult.is_good())
    {
      return setpointResult.status_code();
    }
    auto setpoint = std::move(setpointResult).value();

    // Store the example process value atomically because the read and write functions may execute on
    // different runtime threads. The initial value of 50.0 lies in the documented valid range.
    auto setpointValue = std::make_shared<std::atomic<double>>(50.0);
    auto setpointSourceResult = setpoint.try_set_value_source_sync(ua::make_value_source(
      [setpointValue](const ua::ValueSource::ReadContext& /*context*/,
        const ua::Node& /*node*/,
        const ua::ReadValueId& read,
        std::function<void(ua::DataValueResult)>
          complete)
      {
        // Return the latest accepted value with fresh source and server timestamps.
        ua::DataValue value;
        value.value() = setpointValue->load();
        value.server_timestamp() = ua::DateTime::now();
        value.source_timestamp() = value.server_timestamp();
        ua::index_range_utils::apply_to_value(value, read.index_range());
        complete(std::move(value));
      },
      [setpointValue, setpointId = setpoint.node_id(), applicationLogger](
        const ua::ValueSource::WriteContext& /*context*/,
        const ua::Node& /*node*/,
        const ua::WriteValue& write,
        std::function<void(ua::ValueSource::WriteResult)>
          complete) mutable
      {
        // A scalar setpoint cannot take a partial write.
        if (!write.index_range().empty())
        {
          complete(ua::ValueSource::WriteResult{ua::StatusCode{ua::Status::BadWriteNotSupported}});
          return;
        }
        // Validate before changing application state. A rejected value is logged with its complete
        // ErrorDetail and returned to the Write service unchanged.
        auto validated = try_validate_setpoint(write.value(), setpointId);
        if (!validated.is_good())
        {
          log_rejection(applicationLogger, "Setpoint rejected an invalid write", validated.status_code());
          complete(ua::ValueSource::WriteResult{validated.status_code(), validated.shared_detail()});
          return;
        }
        setpointValue->store(validated.value());
        complete(ua::ValueSource::WriteResult{ua::ValueSource::Written{}});
      }));
    if (!setpointSourceResult.is_good())
    {
      return setpointSourceResult.status_code();
    }

    // Bind Divide through the generated typed handler API. The Method and its owning Demo Object
    // both inherit Call permission from the namespace; the generated Method identifier is retained
    // only to add precise node context to failures.
    const ua::NodeId divideId{namespaceIndex, static_cast<std::uint32_t>(model::MethodId::Demo_Divide)};
    auto divideHandlerResult = demo.try_set_divide_handler_sync(
      [applicationLogger, divideId](
        const ua::MethodCall&, const model::Demo::DivideInputArguments& inputs) mutable
      -> ua::MethodResult<model::Demo::DivideOutputArguments>
      {
        // Keep domain validation separate from transport handling. Failures are logged with their
        // ErrorDetail and returned as the Method's result; successful calls return the named quotient.
        auto quotient = try_divide(inputs.numerator, inputs.divisor, divideId);
        if (!quotient.is_good())
        {
          log_rejection(applicationLogger, "Divide rejected an invalid request", quotient.status_code());
          return quotient.status_code();
        }
        return model::Demo::DivideOutputArguments{.quotient = quotient.value()};
      });
    if (!divideHandlerResult.is_good())
    {
      return divideHandlerResult.status_code();
    }

    return ua::VoidResult{};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

}  // namespace reduktive::reference
