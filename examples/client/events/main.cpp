// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Being told when something happens, rather than watching a value for it.
///
/// It talks to `examples/server/events`, which must already be running. Start that
/// first, in another terminal, then run this.
///
/// A Subscription reports that a value changed. An event reports that something *happened*, with
/// its own message, severity, and source. This client subscribes to the server's events, fills the
/// tank below its threshold and sees nothing, then fills it past the threshold and is told.

#include "example_pki.h"
#include "example_queue.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_call_method_result.h"
#include "ua_client.h"
#include "ua_client_monitored_item.h"
#include "ua_connection.h"
#include "ua_easy_connect_policy.h"
#include "ua_error_detail.h"
#include "ua_event_subscriber.h"
#include "ua_exceptions.h"
#include "ua_hierarchical_path.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_runtime.h"
#include "ua_typed_access.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4843";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:tank";
constexpr double smallFill = 40.0;
constexpr double fillPastThreshold = 45.0;
constexpr auto eventBudget = 10s;
constexpr auto quietBudget = 2s;
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

/// Translates a BrowseName path beneath Objects into the NodeId this server chose.
ua::NodeId resolve(ua::client::Connection& connection, std::uint16_t namespaceIndex,
  std::initializer_list<std::string_view> targetNames)
{
  return connection.typed().resolve_path_sync(ua::NodeId{ua::ObjectId::ObjectsFolder},
    ua::hierarchical_path(namespaceIndex, std::vector<std::string>(targetNames.begin(), targetNames.end())));
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/events", "Be told when something happens, not just when a value changes.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpointUrl);
    const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
    const ua::NodeId tank = resolve(connection, namespaceIndex, {"Tank"});
    const ua::NodeId fill = resolve(connection, namespaceIndex, {"Tank", "Fill"});
    examples::step(1, fmt::format("Connected to {} and resolved Tank/Fill", endpointUrl));

    // Events are published by a notifier, not by the node that caused them. The Server Object is
    // the notifier every server has, and it reports events from anywhere in the address space.
    // The callback runs on the subscriber's own strand and must not block, so it appends to the
    // queue and returns; everything slow happens on this thread.
    auto received = std::make_shared<examples::Queue<ua::client::EventNotification>>();
    ua::client::EventSubscriber subscriber = connection.events();
    subscriber.subscribe_sync(ua::client::EventSubscription{},
      [received](ua::client::EventNotification event) { received->push(std::move(event)); });
    examples::step(2, "Subscribed to events from the Server Object");

    // A fill that stays below the threshold changes the Level but is not an event.
    connection.typed().call_method_sync(tank, fill, ua::client::args(smallFill));
    const bool eventRaised = received->take(quietBudget).has_value();
    examples::step(
      3, fmt::format("Filled by {} (below the threshold), event raised: {}", smallFill, eventRaised));

    // This one crosses it, so the server raises an event and every subscriber is told.
    connection.typed().call_method_sync(tank, fill, ua::client::args(fillPastThreshold));
    const auto event = received->take(eventBudget);
    if (!event)
    {
      throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
        ua::ErrorDetail::build("ExampleEventTimeout",
          "The server raised no event after the tank crossed its high threshold",
          "client.events")}};
    }
    examples::step(4, fmt::format("Filled by {} (past the threshold), event received", fillPastThreshold));
    // An event carries more than a value: who raised it, how urgent it is, and what happened.
    examples::detail(fmt::format("Source:   {}", std::string_view{event->sourceName}));
    examples::detail(fmt::format("Severity: {}", event->severity));
    examples::detail(fmt::format("Message:  {}", std::string_view{event->message.text()}));

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(5, "Closed the Session and stopped the client");

    examples::finished("client/events");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/events", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/events: {}\n", failure.what());
  }
  return 1;
}
