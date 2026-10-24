// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "readings.h"

#include "example_support.h"

#include "ua_eu_information.h"
#include "ua_range.h"
#include "ua_variant.h"

#include <fmt/format.h>

#include <cstdint>
#include <string_view>
#include <utility>

namespace examples::readings
{
namespace
{
// How often the server samples the node, how often it publishes what it collected, and how many
// notifications it may hold for the item before the oldest is dropped.
constexpr double publishingIntervalMs = 100.0;
constexpr double samplingIntervalMs = 50.0;
constexpr std::uint32_t queueSize = 10;
}  // namespace

/// Renders an AnalogItem's value the way a display would: the number, its range, and its units.
///
/// Resolving the handle reads the node's Properties once; `read_sync` then returns the value beside
/// them. EURange is Mandatory on the type, so it is always there; units and instrument range are
/// Optional, and absent ones arrive as an empty optional rather than a fabricated default.
std::string describe(const ua::client::AnalogItemValue& reading)
{
  const std::string units = reading.engineeringUnits
                              ? std::string{std::string_view{reading.engineeringUnits->display_name().text()}}
                              : std::string{"no units published"};
  return fmt::format("{} {}, range {} to {}",
    reading.value.value().to<double>().value(),
    units,
    reading.euRange->low(),
    reading.euRange->high());
}

/// Monitors the node with the filter the SDK composed, appending every reported value to @p values.
ua::client::MonitoredItem monitor_with(ua::client::Subscription& subscription, const ua::NodeId& node,
  ua::DataChangeFilter filter, std::shared_ptr<examples::Queue<double>> values)
{
  ua::client::MonitorRequest request;
  request.nodeId = node;
  request.samplingIntervalMs = samplingIntervalMs;
  request.queueSize = queueSize;
  request.filter = std::move(filter);
  // The callback runs on the subscriber's own strand and must not block, so it appends and returns.
  return subscription.monitor_sync(std::move(request),
    [values](ua::client::DataChangeEvent event)
    {
      const auto value = event.value.value().to<double>();
      if (value.is_good())
      {
        values->push(value.value());
      }
    });
}

/// Reports the Pump's state together with the name this server gives it.
///
/// A Boolean on its own says `true`. The type's two Mandatory Properties say what `true` means, so a
/// display can label the state without the meaning being agreed out of band.
void report_pump_state(ua::client::TwoStateDiscreteHandle& pump)
{
  const ua::client::TwoStateDiscreteValue state = pump.read_sync();
  examples::detail(fmt::format("{}, which this server calls '{}'",
    state.state,
    std::string_view{(state.state ? state.trueState : state.falseState).text()}));
}

/// Creates the Subscription and monitors the node through the filter the SDK composed.
ua::client::Subscription watch_with_deadband(ua::client::Connection& connection, const ua::NodeId& node,
  ua::DataChangeFilter filter, std::shared_ptr<examples::Queue<double>> values)
{
  ua::client::SubscriptionConfig config;
  config.publishingIntervalMs = publishingIntervalMs;
  ua::client::Subscription subscription = connection.subscriptions().create_sync(config);
  monitor_with(subscription, node, std::move(filter), std::move(values));
  return subscription;
}

}  // namespace examples::readings
