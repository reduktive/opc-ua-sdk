// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief A server whose certificate and trust list can be managed over OPC UA.
///
/// Push-model certificate management means the *server* exposes the operations and an administrative
/// client drives them: ask the server for a signing request, take it to your CA, push the signed
/// certificate back, and apply. The alternative, pull-model, has the server fetch from a Global
/// Discovery Server instead; this SDK's pull-model support is incomplete and is not exampled.
///
/// The SDK activates the push service by itself when the server has an application-group certificate
/// store and a crypto provider - which is to say whenever it was built with real credentials rather
/// than SDK-generated development defaults. There is nothing to switch on. What the application does
/// have to decide is *who* may use it: every one of these Methods is gated on the SecurityAdmin Role,
/// and this server grants it to exactly one named account.
///
/// Run `examples/client/push_certificates` against it. The server runs until you press Ctrl+C.

#include "example_pki.h"
#include "example_support.h"

#include "ua_access_identity_facts.h"
#include "ua_application_configuration.h"
#include "ua_built_in_authenticators.h"
#include "ua_exceptions.h"
#include "ua_identity_criteria_type.h"
#include "ua_role_configuration.h"
#include "ua_runtime.h"
#include "ua_secure_string.h"
#include "ua_server.h"
#include "ua_user_token_type.h"

#include <fmt/format.h>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace
{
// Change these for your server.
constexpr std::string_view defaultBindAddress = "127.0.0.1:4849";
constexpr std::string_view adminUser = "security-admin";
constexpr std::string_view operatorUser = "operator";
// Not for production: password constants compiled into the program. A deployment verifies against a
// directory service or a password store, and never holds a plaintext password at all.
constexpr std::string_view adminPassword = "admin-secret";
constexpr std::string_view operatorPassword = "operator-secret";

/// Accepts the two accounts this server knows about.
///
/// Not for production: a constant-string comparison. A deployment checks a salted hash, and takes
/// the same time to answer whether or not the account exists.
std::shared_ptr<ua::server::UserAuthenticator> accepted_identities()
{
  auto composite = std::make_shared<ua::server::CompositeAuthenticator>();
  composite->add(ua::UserTokenKind::UserName,
    std::make_shared<ua::server::SimpleUserPasswordAuthenticator>(
      [](std::string_view username, const ua::SecureString& password)
      {
        const std::string_view presented{password.c_str()};
        return (username == adminUser && presented == adminPassword) ||
               (username == operatorUser && presented == operatorPassword);
      }));
  return composite;
}

/// Grants SecurityAdmin to one account, and Operator to the other.
///
/// This is the whole access-control decision for certificate management. Every push Method - and the
/// TrustList behind them - is refused to a Session that does not hold SecurityAdmin, whatever else
/// that Session is allowed to do. Naming the account explicitly, rather than granting the Role to
/// everyone who authenticated, is the point.
std::shared_ptr<ua::server::RoleConfiguration> identity_role_map()
{
  return ua::server::RoleConfiguration::from_well_known_grants({{ua::server::WellKnownRole::SecurityAdmin,
                                                                  ua::IdentityCriteriaType::UserName,
                                                                  ua::String{std::string{adminUser}}},
    {ua::server::WellKnownRole::Operator,
      ua::IdentityCriteriaType::UserName,
      ua::String{std::string{operatorUser}}}});
}

/// Creates the server and hands it to the Runtime to own.
///
/// The certificate store passed here is the server's application group. Its presence, together with
/// the crypto provider, is what makes the push service live: a server constructed with SDK-generated
/// development defaults has no application group to manage and answers those Methods accordingly.
ua::server::Server& create_server(ua::Runtime& runtime, const examples::DevelopmentPki& pki)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Server)};

  ua::server::ServerComponents components;
  components.crypto = pki.crypto;
  components.applicationGroupCertificateStore = pki.store;
  components.authenticator = accepted_identities();
  components.roleConfiguration = identity_role_map();

  return runtime.attach(ua::server::Server::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .server = ua::server::ServerConfig{}},
    std::move(components)));
}

/// Opens the listener and advertises one secure endpoint accepting username/password.
///
/// No anonymous policy is offered at all. Certificate management is an administrative surface, and
/// an endpoint that accepts anonymous Sessions on the same channel is one configuration mistake away
/// from exposing it.
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
    ua::server::create_user_token_policy(ua::UserTokenType::UserName, ua::SecurityPolicyId::Basic256Sha256));
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
      "server/push_certificates", "Let one named administrator manage this server's certificates.");

    const std::string_view listenAddress = examples::option_value(argc, argv, "--listen", defaultBindAddress);

    ua::Runtime runtime{{.threads = 4}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Server);
    examples::step(1, "Opened the PKI that the push service will manage");

    ua::server::Server& server = create_server(runtime, pki);
    examples::step(
      2, fmt::format("SecurityAdmin granted to '{}', Operator to '{}'", adminUser, operatorUser));
    examples::detail("The push Methods under ServerConfiguration are live; nothing switches them on.");

    const std::string endpointUrl = start_secure_server(server, listenAddress);
    examples::step(3, "Listening, one Basic256Sha256 SignAndEncrypt endpoint, username tokens only");
    examples::detail(endpointUrl);
    examples::wait_for_shutdown_signal(
      runtime.executor(), "Run example_client_push_certificates in another terminal. Press Ctrl+C to stop.");
    runtime.shutdown().value();
    examples::step(4, "Stopped on Ctrl+C");

    examples::finished("server/push_certificates");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("server/push_certificates", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  server/push_certificates: {}\n", failure.what());
  }
  return 1;
}
