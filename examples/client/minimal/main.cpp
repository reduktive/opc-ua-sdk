// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief The smallest standalone OPC UA client: connect securely, read a value, write it, close.
///
/// It talks to `examples/server/minimal`, which must already be running. Start that first, in
/// another terminal, then run this.
///
/// Nodes are found by namespace URI and BrowseName rather than by a hard-coded NodeId, because a
/// numeric namespace index is assigned by each server and is not portable between them.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_hierarchical_path.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_runtime.h"
#include "ua_typed_access.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <chrono>
#include <string>
#include <string_view>
#include <utility>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4840";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:minimal";
constexpr std::string_view folderName = "Demo";
constexpr std::string_view variableName = "Setpoint";
constexpr double newSetpoint = 42.5;
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

/// Discovers the server's endpoints, selects the strongest one both sides can speak, and opens a
/// Session on it. The returned Connection manages the channel and session for its lifetime.
ua::client::Connection connect(ua::client::Client& client, std::string_view endpointUrl)
{
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.timeout = connectTimeout;
  return client.easy_connect_sync(std::move(policy));
}

/// Resolves `Demo/Setpoint` to the NodeId this particular server gave it.
///
/// The namespace URI is looked up in the server's NamespaceArray to get the index it assigned,
/// then a BrowseName path is translated into a NodeId. Both halves matter: the index is per-server,
/// and the NodeId behind a BrowseName is the server's to choose.
ua::NodeId resolve_setpoint(ua::client::Connection& connection)
{
  const auto namespaces = connection.namespace_table();
  const std::uint16_t namespaceIndex = namespaces->lookup_index(namespaceUri).value();

  return connection.typed().resolve_path_sync(ua::NodeId{ua::ObjectId::ObjectsFolder},
    ua::hierarchical_path(namespaceIndex, {std::string{folderName}, std::string{variableName}}));
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/minimal", "Connect securely, read a value, write it, and close.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    const examples::DevelopmentPki pki =
      examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
    examples::step(1, "Opened the development PKI");

    ua::client::Client& client = create_client(runtime, pki);
    ua::client::Connection connection = connect(client, endpointUrl);
    examples::step(2, fmt::format("Connected to {}", endpointUrl));

    const ua::NodeId setpoint = resolve_setpoint(connection);
    examples::step(3, "Resolved Demo/Setpoint by namespace URI and BrowseName");

    const double before = connection.read_value_sync<double>(setpoint);
    examples::step(4, fmt::format("Read Setpoint = {}", before));

    connection.write_value_sync(setpoint, ua::Variant{newSetpoint});
    const double after = connection.read_value_sync<double>(setpoint);
    examples::step(5, fmt::format("Wrote Setpoint, read it back = {}", after));

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(6, "Closed the Session and stopped the client");

    examples::finished("client/minimal");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/minimal", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/minimal: {}\n", failure.what());
  }
  return 1;
}
