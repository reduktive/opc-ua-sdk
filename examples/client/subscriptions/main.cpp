// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

/// @file
/// @brief Being told when a value changes, instead of asking for it.
///
/// It talks to `examples/server/minimal`, which must already be running. Start that first, in
/// another terminal, then run this.
///
/// The example monitors one Variable twice in the same Subscription: once with no filter, and once
/// with an absolute deadband. Writing to the Variable then shows exactly what a deadband does - a
/// change smaller than it never reaches the second monitored item at all.

#include "example_pki.h"
#include "example_queue.h"
#include "example_support.h"

#include "ua_application_configuration.h"
#include "ua_client.h"
#include "ua_client_subscription.h"
#include "ua_connection.h"
#include "ua_data_change_filter.h"
#include "ua_deadband_type.h"
#include "ua_easy_connect_policy.h"
#include "ua_exceptions.h"
#include "ua_namespace_table.h"
#include "ua_object_id.h"
#include "ua_hierarchical_path.h"
#include "ua_runtime.h"
#include "ua_typed_access.h"
#include "ua_utilities.h"
#include "ua_error_detail.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

using namespace std::chrono_literals;

namespace
{
// Change these for your server.
constexpr std::string_view defaultEndpointUrl = "opc.tcp://127.0.0.1:4840";
constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:minimal";
// How often the server samples the node, how often it publishes what it collected, and how many
// notifications it may hold for the item before the oldest is dropped.
constexpr double publishingIntervalMs = 100.0;
constexpr double samplingIntervalMs = 50.0;
constexpr std::uint32_t queueSize = 10;
constexpr double deadbandPercent = 5.0;
// The three writes the lesson is built from: the first is reported by both items, the second
// moves the value by less than deadbandPercent, and the third moves it past.
//
// firstWrite is 31 rather than 30 because a deadband reports a change only when it is GREATER
// than the deadband: 30 - 25.0, the server's initial value, is exactly 5.0 - the boundary - so the
// filtered item would never report the first write. Its last reported value would stay 25, the
// second write of 32 would be 7 away from it and duly reported, and the example would demonstrate
// the exact opposite of the lesson, or pass only when the sampler happened to miss a write.
constexpr double firstWrite = 31.0;
constexpr double writeInsideDeadband = 32.0;
constexpr double writeOutsideDeadband = 50.0;
constexpr auto notificationBudget = 10000ms;
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

/// Resolves `Demo/Setpoint` to the NodeId this server gave it.
ua::NodeId resolve_setpoint(ua::client::Connection& connection)
{
  const std::uint16_t namespaceIndex = connection.namespace_table()->lookup_index(namespaceUri).value();
  return connection.typed().resolve_path_sync(
    ua::NodeId{ua::ObjectId::ObjectsFolder}, ua::hierarchical_path(namespaceIndex, {"Demo", "Setpoint"}));
}

/// A filter that reports a change only once the value has moved by MORE than @p deadband.
///
/// Strictly more: a change of exactly @p deadband is suppressed, not reported.
///
/// The server applies it, so a suppressed change costs no network traffic at all. That is the
/// point of a deadband on a noisy signal.
ua::DataChangeFilter absolute_deadband(double deadband)
{
  ua::DataChangeFilter filter;
  filter.trigger() = ua::DataChangeTrigger::StatusValue;
  filter.deadband_type() = ua::utils::to_underlying(ua::DeadbandType::Absolute);
  filter.deadband_value() = deadband;
  return filter;
}

/// Attaches a monitored item, and hands back the queue every value it reports is appended to.
std::shared_ptr<examples::Queue<double>> monitor(ua::client::Subscription& subscription,
  const ua::NodeId& node, std::variant<std::monostate, ua::DataChangeFilter, ua::AggregateFilter> filter)
{
  auto queue = std::make_shared<examples::Queue<double>>();
  ua::client::MonitorRequest request;
  request.nodeId = node;
  request.samplingIntervalMs = samplingIntervalMs;
  request.queueSize = queueSize;
  request.filter = std::move(filter);
  subscription.monitor_sync(std::move(request),
    [queue](ua::client::DataChangeEvent event)
    {
      const auto value = event.value.value().to<double>();
      if (value.is_good())
      {
        queue->push(value.value());
      }
    });
  return queue;
}

/// Takes the next value, or fails saying which notification never arrived.
double take_or_throw(examples::Queue<double>& queue, std::string_view what)
{
  const auto value = queue.take(notificationBudget);
  if (!value)
  {
    throw ua::UaException{ua::StatusCode{ua::Status::BadTimeout,
      ua::ErrorDetail::build("ExampleNotificationTimeout",
        fmt::format("No notification arrived for {}", what),
        "client.subscriptions")}};
  }
  return *value;
}

/// Reports the value each monitored item was handed when it was created.
///
/// A monitored item reports the current value as soon as it exists, before anything changes, so
/// both items answer here even though nothing has been written yet.
void report_initial_values(examples::Queue<double>& unfiltered, examples::Queue<double>& filtered)
{
  examples::detail(
    fmt::format("Initial value, unfiltered: {}", take_or_throw(unfiltered, "the initial value")));
  examples::detail(
    fmt::format("Initial value, deadband:   {}", take_or_throw(filtered, "the initial value")));
}

}  // namespace

int main(int argc, char** argv)
{
  try
  {
    examples::banner("client/subscriptions", "Be told when a value changes, instead of asking for it.");

    const std::string_view endpoint = examples::option_value(argc, argv, "--endpoint", defaultEndpointUrl);

    ua::Runtime runtime{{.threads = 2}};
    ua::client::Connection connection = connect(runtime, endpoint);
    const ua::NodeId setpoint = resolve_setpoint(connection);
    examples::step(1, fmt::format("Connected to {} and resolved Demo/Setpoint", endpoint));

    // One Subscription carries many monitored items and one Publish stream. The server may revise
    // the interval it was asked for, and reports what it actually chose.
    ua::client::SubscriptionConfig config;
    config.publishingIntervalMs = publishingIntervalMs;
    ua::client::Subscription subscription = connection.subscriptions().create_sync(config);
    examples::step(
      2, fmt::format("Created a Subscription, revised interval {} ms", subscription.publishing_interval()));

    auto unfiltered = monitor(subscription, setpoint, std::monostate{});
    auto filtered = monitor(subscription, setpoint, absolute_deadband(deadbandPercent));
    examples::step(
      3, fmt::format("Monitored Setpoint twice: no filter, and a {} absolute deadband", deadbandPercent));

    report_initial_values(*unfiltered, *filtered);

    connection.write_value_sync(setpoint, ua::Variant{firstWrite});
    // BOTH items report this one - it clears the deadband - so take both. Draining only the
    // unfiltered queue leaves the filtered item's notification sitting there, and step 5 then reads
    // it as the answer to the two writes that follow, reporting the first write's value as though
    // the deadband had let the second through.
    const double unfilteredFirst = take_or_throw(*unfiltered, "the first write");
    const double filteredFirst = take_or_throw(*filtered, "the first write on the filtered item");
    examples::step(4,
      fmt::format("Wrote {}, unfiltered item reported {}, deadband item reported {}",
        firstWrite,
        unfilteredFirst,
        filteredFirst));

    // The second write moves the value by less than deadbandPercent, so the server never reports it on
    // the filtered item. The third moves it past, so that item's next value is the third and never
    // the second.
    connection.write_value_sync(setpoint, ua::Variant{writeInsideDeadband});
    connection.write_value_sync(setpoint, ua::Variant{writeOutsideDeadband});
    examples::step(5,
      fmt::format("Wrote {} then {}, deadband item's next value was {}",
        writeInsideDeadband,
        writeOutsideDeadband,
        take_or_throw(*filtered, "the write past the deadband")));

    subscription.close_sync();
    connection.close_sync();
    runtime.shutdown().value();
    examples::step(6, "Closed the Subscription, the Session, and the client");

    examples::finished("client/subscriptions");
    return 0;
  }
  catch (const ua::UaException& failure)
  {
    examples::print_failure("client/subscriptions", failure.status_code());
  }
  catch (const std::exception& failure)
  {
    fmt::print(stderr, "\nFAILED  client/subscriptions: {}\n", failure.what());
  }
  return 1;
}
