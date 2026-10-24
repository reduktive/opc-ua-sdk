// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_CUSTOM_TYPES_PUMP_READING_H
#define UASDK_EXAMPLE_CUSTOM_TYPES_PUMP_READING_H

/// @file
/// @brief The custom DataType this example defines, and the nodes that publish it.

#include "ua_address_space.h"
#include "ua_structure_definition.h"

#include <cstdint>
#include <memory>
#include <string_view>

namespace examples::pump
{

/// The namespace the custom type and its values live in.
inline constexpr std::string_view namespaceUri = "urn:reduktive:opcua-sdk:example:types";

/// The DataType's BrowseName, as clients will see it.
inline constexpr std::string_view typeName = "PumpReading";

/// Publishes the DataType node and its Default Binary encoding node.
///
/// @param addressSpace  Address space the nodes are created in.
/// @param namespaceIndex Index this example's namespace was assigned.
/// @return The definition the type was published with, for building values of it.
std::shared_ptr<ua::StructureDefinition> publish_data_type(
  ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex);

/// Adds `Pump/Reading`, a Variable holding one value of the custom type.
///
/// @param addressSpace   Address space the nodes are created in.
/// @param namespaceIndex Index this example's namespace was assigned.
/// @param definition     The definition returned by @ref publish_data_type.
void add_reading_variable(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex,
  const std::shared_ptr<ua::StructureDefinition>& definition);

}  // namespace examples::pump

#endif  // UASDK_EXAMPLE_CUSTOM_TYPES_PUMP_READING_H
