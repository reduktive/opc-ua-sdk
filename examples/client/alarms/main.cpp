// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Tracking what is currently wrong, and acknowledging it.
///
/// It talks to `examples/server/alarms`, which must already be running. Start that first, in another
/// terminal, then run this.
///
/// `examples/client/events` receives events: something happened, and you either heard it or you did
/// not. An alarm has state, and that changes what a client does with it. Refreshing asks the server
/// to replay everything currently retained, so a client that has just connected knows what is wrong
/// without waiting for the next change. Acknowledging tells the server an operator has seen it.
///
/// `AlarmConditionTracker` keeps that state for you: it subscribes, follows the condition events, and
/// answers "what is active right now?" from its own view rather than from a replay you must interpret.

#include "example_pki.h"
#include "example_queue.h"
#include "alarm_view.h"
#include "example_support.h"

#include "ua_alarm_condition_tracker.h"
#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_connection.h"
#include "ua_easy_connect_policy.h"
#include "ua_error_detail.h"
#include "ua_event_subscriber.h"
#include "ua_exceptions.h"
#include "ua_hierarchical_path.h"
#include "ua_localized_text.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_runtime.h"
#include "ua_to_string.h"
#include "ua_typed_access.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <thread>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4851";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:alarms";
constexpr std::string_view objectName = "Boiler";
constexpr std::string_view methodName = "Heat";
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;
// Enough to cross the server's threshold of 90 from its starting 20, then enough to fall back under.
constexpr double heatPastThreshold = 75.0;
constexpr double coolBelowThreshold = -75.0;

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
  // Identity, client, connection: covered properly by examples/client/minimal, gathered here so
  // main() gets to the subject.
  const examples::DevelopmentPki pki =
    examples::open_development_pki(runtime.executor(), examples::PkiRole::Client);
  ua::client::Client& client = create_client(runtime, pki);
  ua::client::EasyConnectConfig policy;
  policy.endpointUrl = std::string{endpointUrl};
  policy.timeout = connectTimeout;
  return client.easy_connect_sync(std::move(policy));
}

/// Translates a BrowseName path beneath `Objects` into the NodeId this server chose.
ua::NodeId resolve(ua::client::Connection& connection, std::initializer_list<std::string_view> targetNames)
{
  const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
  return connection.typed().resolve_path_sync(ua::NodeId{ua::ObjectId::ObjectsFolder},
    ua::hierarchical_path(namespaceIndex, std::vector<std::string>(targetNames.begin(), targetNames.end())));
}

/// Drives the server's temperature by @p delta.
void heat_by(
  ua::client::Connection& connection, const ua::NodeId& object, const ua::NodeId& method, double delta)
{
  connection.typed().call_method_sync(object, method, ua::client::args(delta));
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/alarms", "Track what is currently wrong, then acknowledge it.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpointUrl);
    const ua::NodeId boiler = resolve(connection, {objectName});
    const ua::NodeId heat = resolve(connection, {objectName, methodName});
    examples::step(1, fmt::format("Connected to {}", endpointUrl));

    // The tracker subscribes for condition events and keeps the state they describe, so the rest of
    // this program asks it questions instead of interpreting a stream.
    ua::client::AlarmConditionTracker alarms = connection.alarms();
    examples::alarms::await_tracker_attached(connection);
    alarms.refresh_sync();
    examples::step(
      2, fmt::format("Refreshed: {}", examples::alarms::describe(alarms.list_conditions_sync())));

    heat_by(connection, boiler, heat, heatPastThreshold);
    examples::alarms::await_state(
      alarms, examples::alarms::AlarmState{true, false}, "active and unacknowledged");
    examples::step(3,
      fmt::format(
        "Heated past the threshold: {}", examples::alarms::describe(alarms.list_conditions_sync())));

    // Cooling makes the alarm inactive. It does NOT make it finished: it stays retained and
    // unacknowledged, because somebody still has to say they saw it.
    // Acknowledged while it is still active: an operator has seen it, and it has not gone away.
    // Active and acknowledged are independent, which is why a condition carries both.
    examples::alarms::acknowledge_first(alarms);
    examples::step(
      4, fmt::format("Acknowledged: {}", examples::alarms::describe(alarms.list_conditions_sync())));

    heat_by(connection, boiler, heat, coolBelowThreshold);
    examples::alarms::await_cleared(alarms);
    examples::step(5,
      fmt::format("Cooled back down, nothing left to act on: {}",
        examples::alarms::describe(alarms.list_conditions_sync())));

    connection.close_sync();
    runtime.shutdown().value();
    examples::step(6, "Closed the Session and stopped the client");

    examples::finished("client/alarms");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/alarms", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/alarms: {}\n", failure.what());
  }
  return 1;
}
