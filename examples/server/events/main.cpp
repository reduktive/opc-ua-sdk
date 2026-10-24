// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Raising an OPC UA event when something happens in the model.
///
/// The server publishes a `Tank` with a `Level` and a `Fill` Method. Filling the tank past its
/// high threshold raises an event, which any subscribed client is told about. Filling it below the
/// threshold raises nothing, so the difference is easy to see.
///
/// Run `examples/client/events` against it.

#include "example_pki.h"
#include "example_support.h"

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_attribute_id.h"
#include "ua_built_in_authenticators.h"
#include "ua_call_method_result.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_exceptions.h"
#include "ua_generic_event.h"
#include "ua_localized_text.h"
#include "ua_method_adapter.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_utilities.h"
#include "ua_variabletype_id.h"
#include "ua_variant.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{
// Change these for your server.
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:tank";
constexpr std::string_view defaultBindAddress = "127.0.0.1:4843";
constexpr double initialLevel = 10.0;
constexpr double highThreshold = 90.0;
constexpr std::uint16_t highSeverity = 700;

/// Creates the server and hands it to the Runtime to own.
ua::server::Server& create_server(ua::Runtime& runtime, const examples::DevelopmentPki& pki)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Server)};

  ua::server::ServerComponents components;
  components.crypto = pki.crypto;
  components.applicationGroupCertificateStore = pki.store;
  components.authenticator = std::make_shared<ua::server::AnonymousAuthenticator>();
  components.roleConfiguration = ua::server::RoleConfiguration::from_well_known_grants(
    {{ua::server::WellKnownRole::Observer, ua::IdentityCriteriaType::Anonymous}});

  return runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
}

/// Registers the model's namespace with the permissions its nodes inherit.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  const std::vector<ua::RolePermissionType> observerMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Observer,
      ua::PermissionType{ua::PermissionType::Bit::Browse,
        ua::PermissionType::Bit::Read,
        ua::PermissionType::Bit::Call,
        ua::PermissionType::Bit::ReceiveEvents})};
  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, observerMay, {}));
}

/// Builds `Tank` with a `Level` Variable and a `Fill` Method, and returns the Tank's NodeId.
ua::NodeId add_tank(ua::AddressSpace& addressSpace, ua::server::Server& server, std::uint16_t namespaceIndex)
{
  const ua::NodeId tankId{namespaceIndex, "Tank"};
  ua::NodeAccessor tank = addressSpace.create_node_sync(tankId, ua::NodeClass::Object);
  tank.set_browse_name(ua::QualifiedName{namespaceIndex, "Tank"});
  tank.set_display_name(ua::LocalizedText{"", "Tank"});
  tank.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::BaseObjectType});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, tankId);

  const ua::NodeId levelId{namespaceIndex, "Tank.Level"};
  ua::VariableAccessor level =
    addressSpace.create_node_sync(levelId, ua::NodeClass::Variable).as<ua::VariableAccessor>().value();
  level.set_browse_name(ua::QualifiedName{namespaceIndex, "Level"});
  level.set_display_name(ua::LocalizedText{"", "Level"});
  level.set_data_type(ua::NodeId{ua::DataTypeId::Double});
  level.set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead});
  level.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
  tank.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, levelId);
  level.write_value_sync(initialLevel);

  const ua::NodeId fillId{namespaceIndex, "Tank.Fill"};
  ua::NodeAccessor fillNode = addressSpace.create_node_sync(fillId, ua::NodeClass::Method);
  ua::MethodAccessor fill = fillNode.as<ua::MethodAccessor>().value();
  fill.set_browse_name(ua::QualifiedName{namespaceIndex, "Fill"});
  fill.set_display_name(ua::LocalizedText{"", "Fill"});
  fill.set_executable(true);
  tank.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, fillId);

  // The handler adds to the level, and raises an event only when the result crosses the high
  // threshold. Raising an event is what makes a change visible to a client that is not polling.
  using FillArguments = std::tuple<double>;
  auto handler = [level, tankId, &server](const ua::NodeId&,
                   const FillArguments& arguments,
                   std::shared_ptr<const ua::MethodCallContext>,
                   ua::CallMethodResult result,
                   ua::CallMethodCompleteCallback complete) mutable
  {
    // The handler runs on a thread of the server's executor, where the synchronous forms refuse
    // (Bad_WouldBlock): it reads and writes through the asynchronous forms and answers once, from the
    // last completion.
    ua::ReadValueId nodeToRead;
    nodeToRead.node_id() = level.get_node_id();
    nodeToRead.attribute_id() = ua::utils::to_underlying(ua::AttributeId::Value);
    const double added = std::get<0>(arguments);
    level.read_value_async(0.0,
      false,
      nodeToRead,
      nullptr,
      [level, tankId, &server, added, result = std::move(result), complete = std::move(complete)](
        ua::DataValueResult current) mutable
      {
        const auto number = current.is_good()
                              ? current.value().value().to<double>()
                              : ua::Result<double>{current.status_code(), current.shared_detail()};
        if (!number)
        {
          return complete(ua::CallResult{number.status_code(), number.shared_detail()});
        }
        const double filled = number.value() + added;
        level.write_value_async(ua::DataValue{ua::Variant{filled}},
          [filled, tankId, &server, result = std::move(result), complete = std::move(complete)](
            ua::VoidResult written) mutable
          {
            if (written.is_bad())
            {
              return complete(ua::CallResult{written.status_code(), written.shared_detail()});
            }
            if (filled >= highThreshold)
            {
              // GenericEvent carries the mandatory BaseEventType fields as plain members. emit_event fills
              // in EventId, Time, and ReceiveTime, and clamps severity into the range OPC UA allows.
              ua::GenericEvent event{ua::NodeId{ua::ObjectTypeId::BaseEventType}};
              event.sourceNode = tankId;
              event.sourceName = "Tank";
              event.severity = highSeverity;
              event.message =
                ua::LocalizedText{"", fmt::format("Tank level {} reached the high threshold", filled)};
              server.emit_event(event);
            }
            complete(ua::CallResult{std::move(result)});
          });
      });
  };

  auto* callSource = fillNode->method_call_source();
  if (callSource == nullptr)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadNotSupported}};
  }
  const ua::StatusCode installed = callSource->set_call_handler(ua::MethodAdapter<FillArguments>{handler});
  if (!installed.is_good())
  {
    throw ua::UaException{installed};
  }
  return tankId;
}

/// Opens the listener, advertises one secure endpoint, and starts serving.
std::string start_secure_server(ua::server::Server& server, std::string_view listenAddress)
{
  ua::transport::BindAddress bind;
  bind.transportProfileId = ua::TransportProfileId::UaTcpUaScUaBinary;
  bind.address = std::string{listenAddress};
  const ua::server::ListenerHandle listener = server.listen_sync(std::move(bind), {});

  ua::server::ServerEndpointConfig endpoint;
  endpoint.name = "Basic256Sha256-SignAndEncrypt";
  endpoint.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  endpoint.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.userIdentityTokens.push_back(
    ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
  server.add_endpoint(listener, std::move(endpoint));

  server.start_sync();
  return server.advertised_urls(listener).front().str();
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("server/events", "Raise an event when something happens in the model.");

    // A fixed default port, because a server that is reachable at a known address is the whole
    // point; the override is for a machine that already has something listening there.
    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    ua::server::Server& server = create_server(runtime, pki);
    examples::step(1, "Created the server");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = add_namespace(addressSpace);
    add_tank(addressSpace, server, namespaceIndex);
    examples::step(2, fmt::format("Published Tank with Level and Fill, high threshold {}", highThreshold));

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(3, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_events in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(4, "Stopped on Ctrl+C");

    examples::finished("server/events");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/events", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/events: {}\n", failure.what());
  }
  return 1;
}
