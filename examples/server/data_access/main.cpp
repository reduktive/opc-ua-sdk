// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Publishing measurements a client can interpret without asking you what they mean.
///
/// A plain Variable holding 82.5 tells a client a number and nothing else. Is that degrees or bar?
/// What is the sensor's range? Is 82.5 near the top of it? OPC UA Part 8 answers that with the Data
/// Access variable types: the value carries its engineering range and units in Properties beside it,
/// so any client can present it correctly with no prior agreement.
///
/// This server publishes two of them: a `Temperature` as an `AnalogItemType` with an EURange and
/// engineering units, and a `Pump` as a `TwoStateDiscreteType` whose two states have names. The
/// range is what makes a percent deadband possible on the client side.
///
/// Run `examples/client/data_access` against it. The server runs until you press Ctrl+C.

#include "example_pki.h"
#include "example_support.h"
#include "process_model.h"

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
constexpr std::string_view defaultBindAddress = "127.0.0.1:4850";

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
    examples::banner("server/data_access", "Publish measurements that carry their own range and units.");

    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    ua::server::Server& server = create_server(runtime, pki);
    examples::step(1, "Created the server");

    ua::AddressSpace addressSpace = server.address_space();
    const std::uint16_t namespaceIndex = examples::process::add_namespace(addressSpace);
    examples::process::add_process_model(addressSpace, namespaceIndex);
    examples::step(2,
      fmt::format("Published Boiler/Temperature, EURange {} to {} {}",
        examples::process::rangeLow,
        examples::process::rangeHigh,
        examples::process::unitSymbol));
    examples::step(3,
      fmt::format("Published Boiler/Pump, '{}' or '{}'",
        examples::process::pumpTrueState,
        examples::process::pumpFalseState));

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(4, "Listening, one Basic256Sha256 SignAndEncrypt endpoint");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_data_access in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(5, "Stopped on Ctrl+C");

    examples::finished("server/data_access");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/data_access", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/data_access: {}\n", failure.what());
  }
  return 1;
}
