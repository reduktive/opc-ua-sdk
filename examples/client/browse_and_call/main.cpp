// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Discovering a server's model and calling one of its Methods.
///
/// It talks to `examples/server/address_space`, which must already be running. Start that first,
/// in another terminal, then run this.
///
/// Nothing here assumes a NodeId. The client walks the model with a browse cursor, translates a
/// BrowseName path into the NodeId this server chose, reads a Method's declared signature, and
/// then calls it.

#include "example_pki.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_browse_cursor.h"
#include "ua_call_method_result.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_hierarchical_path.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_runtime.h"
#include "ua_to_string.h"
#include "ua_typed_access.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4841";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:plant";
constexpr double scaleFactor = 1.25;
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

/// Discovers the server's endpoints and opens a Session on the strongest one.
ua::client::Connection connect(ua::Runtime& runtime, std::string_view endpointUrl)
{
  // Identity, client, connection: the three steps every client performs, in one place, so that
  // main() gets to the part this example is actually about.
  const examples::DevelopmentPki pki =
    examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
  ua::client::Client& client = create_client(runtime, pki);
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.timeout = connectTimeout;
  return client.easy_connect_sync(std::move(policy));
}

/// Lists a node's hierarchical children, naming each one's NodeClass.
///
/// A cursor hides continuation points: it fetches the next batch when the current one runs out.
/// Close it so the server can release the continuation point it is holding for you.
std::string browse_children(ua::client::Connection& connection, const ua::NodeId& parent)
{
  ua::client::BrowseOptions options;
  options.referenceTypeId = ua::NodeId{ua::ReferenceTypeId::HierarchicalReferences};
  options.includeSubtypes = true;

  ua::client::BrowseCursor cursor = connection.typed().browse(parent, options);
  std::string listed;
  while (cursor.has_more())
  {
    const auto entry = cursor.next_sync();
    listed += listed.empty() ? "" : ", ";
    listed +=
      fmt::format("{} ({})", std::string_view{entry.browseName.name()}, ua::to_string(entry.nodeClass));
  }
  cursor.close_sync();
  return listed;
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/browse_and_call", "Discover a server's model, then call a Method on it.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpointUrl);
    examples::step(1, fmt::format("Connected to {}", endpointUrl));

    const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
    examples::step(2, fmt::format("Resolved {} to namespace index {}", namespaceUri, namespaceIndex));

    // Part 4 allows a path to match several nodes; resolve_path names one local node, or fails saying why.
    examples::step(3, "Browsed the Objects folder for this server's own model");
    const ua::NodeId plant = connection.typed().resolve_path_sync(
      ua::NodeId{ua::ObjectId::ObjectsFolder}, ua::hierarchical_path(namespaceIndex, {"Plant"}));
    examples::detail(fmt::format("Plant contains: {}", browse_children(connection, plant)));

    const ua::NodeId boiler = connection.typed().resolve_path_sync(
      ua::NodeId{ua::ObjectId::ObjectsFolder}, ua::hierarchical_path(namespaceIndex, {"Plant", "Boiler"}));
    examples::step(4, "Translated Plant/Boiler to the NodeId this server chose");
    examples::detail(fmt::format("Boiler contains: {}", browse_children(connection, boiler)));

    const ua::NodeId scale = connection.typed().resolve_path_sync(ua::NodeId{ua::ObjectId::ObjectsFolder},
      ua::hierarchical_path(namespaceIndex, {"Plant", "Boiler", "Scale"}));
    examples::step(5, "Translated the Method's path the same way");

    // A Method is called on the Object that owns it, so a Call names both. The arguments are
    // positional and must match the Method's declared InputArguments.
    const ua::CallResult result =
      connection.typed().call_method_sync(boiler, scale, ua::client::args(scaleFactor));
    const double scaled = result.value().output_arguments()[0].to<double>().value();
    examples::step(6, fmt::format("Called Scale({}), new Setpoint = {}", scaleFactor, scaled));

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(7, "Closed the Session and stopped the client");

    examples::finished("client/browse_and_call");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/browse_and_call", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/browse_and_call: {}\n", failure.what());
  }
  return 1;
}
