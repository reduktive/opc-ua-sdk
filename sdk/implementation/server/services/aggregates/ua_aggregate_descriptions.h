// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_AGGREGATE_DESCRIPTIONS_H
#define UA_AGGREGATE_DESCRIPTIONS_H

#include "ua_object_id.h"

#include <span>
#include <string_view>

namespace ua::server::aggregates
{

struct StandardAggregateDescription
{
  ObjectId objectId;
  std::string_view text;
};

/// Returns the checked-in standard Aggregate descriptions for one language.
/// An empty span means the SDK has no built-in resource for that language.
std::span<const StandardAggregateDescription> standard_aggregate_descriptions(
  std::string_view language) noexcept;

}  // namespace ua::server::aggregates

#endif  // UA_AGGREGATE_DESCRIPTIONS_H
