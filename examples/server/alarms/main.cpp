// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Raising an alarm that stays raised until somebody deals with it.
///
/// `examples/server/events` raises an event: a thing happened, once, and whoever was listening heard
/// it. An alarm is different in the way that matters operationally. It has a state that persists, a
/// client that connects afterwards can ask what is currently wrong, and it is not finished when it
/// stops being true - somebody has to acknowledge it.
///
/// This server publishes a `Boiler` with a `Temperature` and one `AlarmConditionType` condition over
/// it. A `Heat` Method drives the temperature up and down, activating and clearing the alarm, so the
/// whole lifecycle is reachable from a client with no timer to wait for.
///
/// Run `examples/client/alarms` against it. The server runs until you press Ctrl+C.

#include "example_pki.h"
#include "example_support.h"
#include "boiler_alarm.h"

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
constexpr std::string_view defaultBindAddress = "127.0.0.1:4851";

/// Creates the server and hands it to the Runtime to own.
///
/// Operator, not Observer: acknowledging an alarm is a Method call, and a Session that may only
/// look at the model must not be able to clear somebody else's alarm.
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
    {{ua::server::WellKnownRole::Operator, ua::IdentityCriteriaType::Anonymous}});

  return runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
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
    examples::banner("server/alarms", "Raise an alarm that persists until somebody acknowledges it.");

    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    ua::server::Server& server = create_server(runtime, pki);
    examples::step(1, "Created the server");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = examples::boiler::add_namespace(addressSpace);
    const ua::NodeId temperature = examples::boiler::add_boiler(addressSpace, namespaceIndex);
    examples::step(2, "Published Boiler/Temperature and a Heat Method");

    examples::boiler::add_high_temperature_alarm(server, addressSpace, namespaceIndex, temperature);
    examples::step(
      3, fmt::format("Attached a HighTemperature alarm, threshold {}", examples::boiler::highThreshold));

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_alarms in another terminal. Press Ctrl+C to stop.");

    runtime.shutdown().value();
    examples::step(5, "Stopped on Ctrl+C");

    examples::finished("server/alarms");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/alarms", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/alarms: {}\n", failure.what());
  }
  return 1;
}
