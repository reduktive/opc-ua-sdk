// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Publishing a structured DataType the SDK has never heard of.
///
/// OPC UA lets a server define its own DataTypes. A structured one is described by a
/// `StructureDefinition` - a name, a base type, and an ordered field list - which the server
/// publishes as a DataType node, alongside an encoding node naming how instances are encoded on the
/// wire. A client that has never seen the type can read that description and decode values of it.
///
/// The address space is the single source of truth here. Nothing is generated, nothing is compiled
/// in, and no header is shared between the two halves of this example.
///
/// Encodings are UA Binary and UA XML. There is no JSON encoder in this SDK.
///
/// Run `examples/client/custom_types` against it. The server runs until you press Ctrl+C.

#include "example_pki.h"
#include "example_support.h"
#include "pump_reading.h"

#include "ua_access_restriction_type.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_exceptions.h"
#include "ua_permission_type.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"
#include "ua_well_known_role_permissions.h"

#include <fmt/format.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
// Change these for your server.
constexpr std::string_view defaultBindAddress = "127.0.0.1:4848";

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

/// Registers the namespace the custom type and its values live in.
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
    addressSpace.create_namespace(std::string{examples::pump::namespaceUri}, observerMay, secureSessionOnly));
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
    examples::banner("server/custom_types", "Define a DataType of your own and publish values of it.");

    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    ua::server::Server& server = create_server(runtime, pki);
    examples::step(1, "Created the server");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = add_namespace(addressSpace);
    const auto definition = examples::pump::publish_data_type(addressSpace, namespaceIndex);
    examples::step(
      2, fmt::format("Published the {} DataType and its Default Binary encoding", examples::pump::typeName));

    examples::pump::add_reading_variable(addressSpace, namespaceIndex, definition);
    examples::step(3, fmt::format("Published Pump/Reading, a Variable of type {}", examples::pump::typeName));

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_custom_types in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(5, "Stopped on Ctrl+C");

    examples::finished("server/custom_types");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/custom_types", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/custom_types: {}\n", failure.what());
  }
  return 1;
}
