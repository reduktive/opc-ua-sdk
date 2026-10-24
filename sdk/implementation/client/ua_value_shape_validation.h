// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Pure Part 3 ValueRank / ArrayDimensions validation for tier-2 client writes.

#ifndef UA_VALUE_SHAPE_VALIDATION_H
#define UA_VALUE_SHAPE_VALIDATION_H

#include "ua_node_id.h"
#include "ua_result.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace ua
{
class Variant;
}

namespace ua::client::detail
{

struct VariableShape
{
  std::int32_t valueRank{-2};
  std::optional<std::vector<std::uint32_t>> arrayDimensions;
};

/// Validates an outgoing Variant against a Variable's Part 3 shape attributes.
[[nodiscard]] ua::VoidResult validate_variable_write_shape(
  const ua::NodeId& node, const ua::Variant& value, const VariableShape& shape);

}  // namespace ua::client::detail

#endif  // UA_VALUE_SHAPE_VALIDATION_H
