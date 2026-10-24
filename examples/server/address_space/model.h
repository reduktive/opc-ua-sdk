// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_ADDRESS_SPACE_MODEL_H
#define UASDK_EXAMPLE_ADDRESS_SPACE_MODEL_H

/// @file
/// @brief Builds this example's information model in code.

#include "ua_address_space.h"

#include <cstdint>

namespace examples::plant
{

/// Registers the model's namespace and returns the index the server assigned it.
std::uint16_t add_namespace(ua::AddressSpace& addressSpace);

/// Builds `Plant/Boiler` with two Variables and one Method beneath `Objects`.
///
/// Everything here is created node by node: there is no NodeSet file and no generated code, so
/// each reference and attribute a client depends on is visible in one place.
void add_plant(ua::AddressSpace& addressSpace, std::uint16_t namespaceIndex);

}  // namespace examples::plant

#endif  // UASDK_EXAMPLE_ADDRESS_SPACE_MODEL_H
