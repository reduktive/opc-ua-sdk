// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_DATA_ACCESS_PROCESS_MODEL_H
#define UASDK_EXAMPLE_DATA_ACCESS_PROCESS_MODEL_H

/// @file
/// @brief The Data Access model this example publishes.

#include "ua_address_space.h"

#include <cstdint>

namespace examples::process
{

/// The namespace the measurements live in.
inline constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:process";

/// The range the instrument is calibrated for. A client's percent deadband is a percentage of this.
inline constexpr double rangeLow = 0.0;
inline constexpr double rangeHigh = 200.0;

/// The unit symbol the Temperature publishes, echoed in this server's own output.
inline constexpr std::string_view unitSymbol = "degC";

/// The names this server gives the Pump's two states.
inline constexpr std::string_view pumpTrueState = "Running";
inline constexpr std::string_view pumpFalseState = "Stopped";

/// Registers the model's namespace and returns the index the server assigned it.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace);

/// Publishes `Boiler` with a `Temperature` AnalogItemType and a `Pump` TwoStateDiscreteType.
///
/// Both are instantiated through their generated types, so every Property each type mandates is
/// created, typed and referenced correctly - which is what makes them readable as Data Access nodes
/// rather than as plain Variables.
void add_process_model(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex);

}  // namespace examples::process

#endif  // UASDK_EXAMPLE_DATA_ACCESS_PROCESS_MODEL_H
