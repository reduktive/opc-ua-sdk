// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Reading a measurement together with the range and units that give it meaning.
///
/// It talks to `examples/server/data_access`, which must already be running. Start that first, in
/// another terminal, then run this.
///
/// `examples/client/subscriptions` filters a plain Variable with an absolute deadband: "tell me when
/// it moves by 5", which means something only if you already know what 5 means. A percent deadband
/// says "when it moves by 10 percent of the instrument's range", and the client is never told that
/// range: a Data Access node publishes it, and the SDK reads it and composes the filter.

#include "example_pki.h"
#include "example_queue.h"
#include "readings.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_client_subscription.h"
#include "ua_connection.h"
#include "ua_data_access.h"
#include "ua_easy_connect_policy.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_eu_information.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_range.h"
#include "ua_hierarchical_path.h"
#include "ua_runtime.h"
#include "ua_to_string.h"
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
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4850";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:process";
constexpr std::string_view folderName = "Boiler";
constexpr std::string_view analogName = "Temperature";
constexpr std::string_view discreteName = "Pump";
// How long to wait for endpoint discovery and the Session handshake to complete.
constexpr auto connectTimeout = 10s;
// A percentage of the node's own EURange, not of the value. The server publishes a range of 0 to
// 200, so ten percent is twenty degrees.
constexpr double deadbandPercent = 10.0;
// Inside that band, then past it. Only the second is reported.
constexpr double smallChange = 90.0;
constexpr double largeChange = 130.0;
// A percentage no filter can express. PercentDeadband is defined on [0, 100].
constexpr double impossiblePercent = 150.0;
constexpr auto notificationBudget = 10000ms;

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

/// Takes the next reported value, or fails saying which notification never arrived.
double take_or_throw(examples::Queue<double>& values, std::string_view what)
{
  const auto value = values.take(notificationBudget);
  if (!value)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
      ua::ErrorDetail::build("ExampleNotificationTimeout",
        fmt::format("No notification arrived for {}", what),
        "client.data_access")}};
  }
  return *value;
}

/// Writes a change inside the deadband and one past it, and reports what the item delivered.
///
/// The first write moves the value by less than the band, so the server never reports it. The second
/// moves it past, so that is the next value the monitored item yields - never the intermediate one.
double report_deadband_effect(
  ua::client::Connection& connection, const ua::NodeId& node, examples::Queue<double>& values)
{
  connection.write_value_sync(node, ua::Variant{smallChange});
  connection.write_value_sync(node, ua::Variant{largeChange});
  return take_or_throw(values, "the change past the deadband");
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/data_access", "Read a measurement with the range and units that explain it.");

    const std::string_view endpointUrl = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpointUrl);
    examples::step(1, fmt::format("Connected to {}", endpointUrl));

    ua::client::AnalogItemHandle temperature =
      connection.data_access().analog_unit_range_sync(resolve(connection, {folderName, analogName}));
    examples::step(2, fmt::format("Read {} as an AnalogUnitRangeType", analogName));
    examples::detail(examples::readings::describe(temperature.read_sync()));

    ua::client::TwoStateDiscreteHandle pump =
      connection.data_access().two_state_discrete_sync(resolve(connection, {folderName, discreteName}));
    examples::step(3, fmt::format("Read {} as a TwoStateDiscreteType", discreteName));
    examples::readings::report_pump_state(pump);

    // The whole point: the percentage is of the node's own EURange, which the SDK already read.
    auto values = std::make_shared<examples::Queue<double>>();
    ua::client::Subscription subscription = examples::readings::watch_with_deadband(connection,
      temperature.node_id(),
      temperature.make_percent_deadband_filter(deadbandPercent).value(),
      values);
    examples::step(4, fmt::format("Monitored {} with a {} percent deadband", analogName, deadbandPercent));
    examples::detail(fmt::format("Initial value {}", take_or_throw(*values, "the initial value")));

    examples::step(5,
      fmt::format("Wrote {} then {}; the item's next value was {}",
        smallChange,
        largeChange,
        report_deadband_effect(connection, temperature.node_id(), *values)));

    // An expected refusal, and the reason this is worth showing: PercentDeadband is defined on
    // [0, 100], so the SDK rejects this before composing a request. No round trip, no server error.
    const auto impossible = temperature.make_percent_deadband_filter(impossiblePercent);
    examples::step(6,
      fmt::format(
        "A {} percent deadband is refused: {}", impossiblePercent, ua::to_string(impossible.status_code())));
    examples::detail("A percent deadband is a percentage of EURange, so only 0 to 100 can mean anything.");

    subscription.close_sync();
    connection.close_sync();
    runtime.shutdown().value();
    examples::step(7, "Closed the Subscription, the Session, and the client");

    examples::finished("client/data_access");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/data_access", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/data_access: {}\n", failure.what());
  }
  return 1;
}
