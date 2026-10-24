// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Presenting a user identity, and seeing what it changes.
///
/// It talks to `examples/server/authentication`, which must already be running. Start that first,
/// in another terminal, then run this.
///
/// The same Variable is approached three times with three different credentials. Anonymous can read
/// it and is refused the write; a username/password Session and an X.509 Session are both allowed
/// the write. Nothing about the node changed between the attempts - only who was asking.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_crypto_types.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_hierarchical_path.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_runtime.h"
#include "ua_status_code.h"
#include "ua_to_string.h"
#include "ua_typed_access.h"
#include "ua_user_identity.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4844";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:authentication";
constexpr std::string_view operatorUser = "operator";
// Not for production: a password constant compiled into the program. A deployment prompts for it or
// reads it from a secret store, and never puts it on a command line, in a log, or in source.
constexpr std::string_view operatorPassword = "operator-secret";
constexpr double operatorSetpoint = 30.0;
constexpr double certificateSetpoint = 35.0;
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;

/// Creates the client and hands it to the Runtime to own.
ua::client::Client& create_client(ua::Runtime& runtime, const examples::DevelopmentPki& pki)
{
  auto application = ua::ApplicationConfig::load_default();
  application.application_description_part().applicationUri =
    std::string{examples::development_application_uri(examples::PkiRole::Client)};

  return runtime.attach(ua::client::Client::create(runtime.executor(),
    {.identity = ua::ApplicationIdentity::load_default(),
      .application = std::move(application),
      .client = ua::client::ClientConfig{}},
    {.crypto = pki.crypto, .applicationGroupCertificateStore = pki.store}));
}

/// Opens a Session presenting @p identity.
///
/// The identity is carried on the ActivateSession request, inside the already-encrypted channel.
/// Changing it is the only difference between the three connections this example makes.
ua::client::Connection connect_as(
  ua::client::Client& client, std::string_view endpointUrl, ua::client::UserIdentity identity)
{
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.identity = std::move(identity);
  policy.timeout = connectTimeout;
  return client.easy_connect_sync(std::move(policy));
}

/// The client's own certificate and key, presented as a user credential.
///
/// Not for production: an application's certificate identifies the *program*, and a user
/// certificate identifies the *person*. A deployment issues a separate certificate per user and
/// enrols it in the server's user-token trust list.
ua::client::X509Identity certificate_identity(const examples::DevelopmentPki& pki)
{
  const auto own =
    pki.store->try_get_application_certificate_sync(ua::CertificateType::RsaSha256Application).value();
  return ua::client::X509Identity{
    .certificate = own.certificate, .keyPair = own.keys, .issuerCertificates = own.issuerCertificates};
}

/// Resolves `Demo/Setpoint` to the NodeId this server gave it.
ua::NodeId resolve_setpoint(ua::client::Connection& connection)
{
  const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
  return connection.typed().resolve_path_sync(
    ua::NodeId{ua::ObjectId::ObjectsFolder}, ua::hierarchical_path(namespaceIndex, {"Demo", "Setpoint"}));
}

/// Writes @p value and returns what the server holds afterwards, so a step line can report the
/// change the server actually accepted rather than the one that was asked for.
double confirmed_write(ua::client::Connection& connection, const ua::NodeId& node, double value)
{
  connection.write_value_sync(node, ua::Variant{value});
  return connection.read_value_sync<double>(node);
}

/// Attempts a write and reports the status the server answered with, without throwing.
///
/// The non-throwing `try_` form is used here because a refusal is the *expected* outcome of this
/// call and is the thing the example is demonstrating. Every other operation uses the throwing
/// form, so a genuine failure surfaces in one place: the catch in `main()`.
ua::StatusCode refused_write(ua::client::Connection& connection, const ua::NodeId& node, double value)
{
  return connection.try_write_value_sync(node, ua::Variant{value}).status_code();
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/authentication", "The same node, three credentials, three outcomes.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
    ua::client::Client& client = create_client(runtime, pki);
    examples::step(1, fmt::format("Client ready, server at {}", endpointUrl));

    ua::client::Connection anonymous = connect_as(client, endpointUrl, ua::client::AnonymousIdentity{});
    const ua::NodeId setpoint = resolve_setpoint(anonymous);
    examples::step(
      2, fmt::format("Anonymous Session read Setpoint = {}", anonymous.read_value_sync<double>(setpoint)));

    examples::step(3,
      fmt::format("Anonymous Session write refused: {}",
        ua::to_string(refused_write(anonymous, setpoint, operatorSetpoint))));
    examples::detail("The node is writable. The Observer Role this Session holds is not.");
    anonymous.close_sync();

    ua::client::Connection named = connect_as(client,
      endpointUrl,
      ua::client::UsernamePasswordIdentity{
        .username = std::string{operatorUser}, .password = std::string{operatorPassword}});
    examples::step(4,
      fmt::format("Session as '{}' wrote Setpoint = {}",
        operatorUser,
        confirmed_write(named, setpoint, operatorSetpoint)));
    named.close_sync();

    ua::client::Connection byCertificate = connect_as(client, endpointUrl, certificate_identity(pki));
    examples::step(5,
      fmt::format("Session holding an X.509 user certificate wrote Setpoint = {}",
        confirmed_write(byCertificate, setpoint, certificateSetpoint)));
    byCertificate.close_sync();

    runtime.shutdown().value();
    examples::step(6, "Closed all three Sessions and stopped the client");

    examples::finished("client/authentication");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/authentication", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/authentication: {}\n", failure.what());
  }
  return 1;
}
