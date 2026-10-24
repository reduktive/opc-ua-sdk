// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_ALARMS_BOILER_ALARM_H
#define UASDK_EXAMPLE_ALARMS_BOILER_ALARM_H

/// @file
/// @brief The model this example alarms over, and the condition attached to it.

#include "ua_address_space.h"
#include "ua_node_id.h"

#include <cstdint>
#include <string_view>

namespace ua::server
{
class Server;
}

namespace examples::boiler
{

/// The namespace the boiler lives in.
inline constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:alarms";

/// The temperature at or above which the alarm is active. A client drives past this with `Heat`.
inline constexpr double highThreshold = 90.0;

/// The severity the alarm reports while it is active, on OPC UA's 1-1000 scale.
inline constexpr std::uint16_t highSeverity = 700;

/// Registers the model's namespace and returns the index the server assigned it.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace);

/// Publishes `Boiler` with a `Temperature` Variable and a `Heat` Method, and returns Temperature.
///
/// `Heat` takes a delta so a client can drive the value across the threshold in either direction
/// on demand, which is what makes the alarm's whole lifecycle reachable without waiting on a timer.
ua::NodeId add_boiler(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex);

/// Attaches an AlarmConditionType condition reporting on @p source, and wires it to the temperature.
///
/// The condition is a node in the address space with state of its own, not a message. It activates
/// when the temperature crosses @ref highThreshold and deactivates when it falls back, and in both
/// cases it stays retained - visible to a client that connects afterwards - until acknowledged.
void add_high_temperature_alarm(ua::server::Server& server, ua::AddressSpace& addressSpace,
  std::uint16_t namespaceIndex, const ua::NodeId& source);

}  // namespace examples::boiler

#endif  // UASDK_EXAMPLE_ALARMS_BOILER_ALARM_H
