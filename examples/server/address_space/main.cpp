// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief A server whose information model is built node by node in code.
///
/// It publishes a namespace of its own containing `Plant/Boiler`: two Variables with different
/// access levels, and a `Scale` Method carrying the argument metadata a client needs to discover
/// its signature. There is no NodeSet file and no generated code, so every reference and attribute
/// a client depends on is visible in one place - see model.cpp.
///
/// Run `examples/client/browse_and_call` against it to browse that model and call the Method.
///
/// The server runs until you press Ctrl+C, then shuts down in order.

#include "example_pki.h"
#include "example_support.h"
#include "model.h"

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_exceptions.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_server.h"

#include <fmt/format.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace
{
// Change these for your server.
constexpr std::string_view defaultBindAddress = "127.0.0.1:4841";

/// Creates the server and hands it to the Runtime to own.
///
/// Anonymous authentication is accepted and mapped to the standard Observer role. A deployment
/// replaces both with its own identities and role mapping.
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

/// Opens the listener, advertises one secure endpoint, and starts serving.
///
/// The endpoint pairs a SecurityPolicy with a MessageSecurityMode and the user identities it
/// accepts. Anonymous is accepted only inside the signed and encrypted channel.
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
    examples::banner(
      "server/address_space", "A server whose information model is built node by node in code.");

    // A fixed default port, because a server that is reachable at a known address is the whole
    // point; the override is for a machine that already has something listening there.
    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    examples::step(1, "Opened the development PKI");

    ua::server::Server& server = create_server(runtime, pki);
    examples::step(2, "Created the server");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = examples::plant::add_namespace(addressSpace);
    examples::plant::add_plant(addressSpace, namespaceIndex);
    examples::step(3, "Built Plant/Boiler with two Variables and one Method");

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_browse_and_call in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(5, "Stopped on Ctrl+C");

    examples::finished("server/address_space");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/address_space", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/address_space: {}\n", failure.what());
  }
  return 1;
}
