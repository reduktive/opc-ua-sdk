// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief A server that dials out to its client instead of waiting to be called.
///
/// Reverse Connect exists for the case where the server is the one behind a firewall. The server
/// opens the TCP connection to a listening client and sends a ReverseHello; from that point on the
/// roles are the usual ones, and the client drives the SecureChannel, the Session, and everything
/// after. Only who dialled is different.
///
/// This server therefore has no listener of its own. It carries the endpoint definitions it would
/// otherwise advertise, and offers them over the connection it makes.
///
/// Run `examples/client/reverse_connect` first, so there is something to dial. The server retries
/// until the client appears, and runs until you press Ctrl+C.

#include "example_pki.h"
#include "example_support.h"

#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_datatype_id.h"
#include "ua_exceptions.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_reverse_connect_handle.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_variabletype_id.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:reverse";
constexpr std::string_view defaultClientUrl = "opc.tcp://127.0.0.1:4870";
// The URL this server advertises for itself in the ReverseHello. Nothing listens there - the server
// dialled out - but the URL is still the server's identity on the wire, so two things constrain it:
// the client matches on it, and its host name must be one the server's certificate covers, or the
// client's certificate validation rejects the channel.
constexpr std::string_view advertisedUrl = "opc.tcp://localhost:4840";
constexpr auto retryInterval = 2s;
constexpr double initialSetpoint = 25.0;

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

/// Registers the namespace and adds one readable Variable, so the Session has something to do.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace)
{
  const std::vector<ua::RolePermissionType> observerMay{
    ua::server::make_well_known_role_permission(ua::server::WellKnownRole::Observer,
      ua::PermissionType{ua::PermissionType::Bit::Browse, ua::PermissionType::Bit::Read})};

  const ua::AccessRestrictionType secureSessionOnly{ua::AccessRestrictionType::Bit::SigningRequired,
    ua::AccessRestrictionType::Bit::EncryptionRequired,
    ua::AccessRestrictionType::Bit::SessionRequired,
    ua::AccessRestrictionType::Bit::ApplyRestrictionsToBrowse};

  return addressSpace.add_namespace_sync(
    addressSpace.create_namespace(std::string{namespaceUri}, observerMay, secureSessionOnly));
}

/// Adds `Demo/Setpoint` beneath `Objects`.
void add_demo_folder(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex)
{
  const ua::NodeId demoId{namespaceIndex, "Demo"};
  ua::NodeAccessor demo = addressSpace.create_node_sync(demoId, ua::NodeClass::Object);
  demo.set_browse_name(ua::QualifiedName{namespaceIndex, "Demo"});
  demo.set_display_name(ua::LocalizedText{"", "Demo"});
  demo.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::ObjectTypeId::FolderType});
  addressSpace.find_node_sync(ua::NodeId{ua::ObjectId::ObjectsFolder})
    .add_reference_sync(ua::NodeId{ua::ReferenceTypeId::Organizes}, demoId);

  const ua::NodeId setpointId{namespaceIndex, "Demo.Setpoint"};
  ua::VariableAccessor setpoint =
    addressSpace.create_node_sync(setpointId, ua::NodeClass::Variable).as<ua::VariableAccessor>().value();
  setpoint.set_browse_name(ua::QualifiedName{namespaceIndex, "Setpoint"});
  setpoint.set_display_name(ua::LocalizedText{"", "Setpoint"});
  setpoint.set_data_type(ua::NodeId{ua::DataTypeId::Double});
  setpoint.set_access_level(ua::AccessLevelType{ua::AccessLevelType::Bit::CurrentRead});
  setpoint.add_reference_sync(
    ua::NodeId{ua::ReferenceTypeId::HasTypeDefinition}, ua::NodeId{ua::VariableTypeId::BaseDataVariableType});
  demo.add_reference_sync(ua::NodeId{ua::ReferenceTypeId::HasComponent}, setpointId);
  setpoint.write_value_sync(initialSetpoint);
}

/// The endpoint this server offers over a reverse connection.
///
/// A reverse-connect target carries its own endpoint definitions rather than borrowing a listener's,
/// because there is no listener. The security terms are the same ones an ordinary endpoint states,
/// and they are not weakened by the direction the TCP connection was made in.
ua::server::ServerEndpointConfig reverse_endpoint()
{
  ua::server::ServerEndpointConfig endpoint;
  endpoint.name = "Basic256Sha256-SignAndEncrypt";
  endpoint.securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
  endpoint.messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
  endpoint.userIdentityTokens.push_back(
    ua::server::create_user_token_policy(ua::UserTokenType::Anonymous, ua::SecurityPolicyId::None));
  return endpoint;
}

/// Starts dialling the client's listener, retrying until it answers.
///
/// The target names the client by its ApplicationUri, so a connection is offered only to the client
/// it was meant for. `periodicConnectInterval` is how often a failed dial is retried, which is what
/// lets the server be started first and simply wait.
ua::server::ReverseConnectHandle dial_client(ua::server::Server& server, std::string_view clientUrl)
{
  ua::server::ServerConfig::ReverseConnectTarget target;
  target.name = "example-client";
  target.clientApplicationUri = std::string{examples::development_application_uri(examples::PkiRole::Client)};
  target.clientEndpointUrl = std::string{clientUrl};
  target.serverEndpointUrl = std::string{advertisedUrl};
  target.endpoints.push_back(reverse_endpoint());
  target.periodicConnectInterval = std::chrono::duration_cast<std::chrono::seconds>(retryInterval);

  server.start_sync();
  return server.start_reverse_connect_sync(std::move(target));
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("server/reverse_connect", "Dial out to a listening client instead of waiting.");

    const std::string_view clientUrl = examples::option_value(argc, argv, "--endpoint", defaultClientUrl);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    ua::server::Server& server = create_server(runtime, pki);
    examples::step(1, "Created the server, with no listener of its own");

    ua::AddressSpace addressSpace = server.address_space();
    add_demo_folder(addressSpace, add_namespace(addressSpace));
    examples::step(2, "Published Demo/Setpoint for the client to read");

    const ua::server::ReverseConnectHandle target = dial_client(server, clientUrl);
    examples::step(3, fmt::format("Dialling {}, retrying every {}s", clientUrl, retryInterval.count()));
    examples::detail(fmt::format("Advertising itself as {}", advertisedUrl));
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_reverse_connect in another terminal. Press Ctrl+C to stop.");
    server.stop_reverse_connect_sync(target);
    runtime.shutdown().value();
    examples::step(4, "Stopped dialling and shut down on Ctrl+C");

    examples::finished("server/reverse_connect");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/reverse_connect", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/reverse_connect: {}\n", failure.what());
  }
  return 1;
}
