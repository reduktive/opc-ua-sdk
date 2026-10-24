// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_value_source.h"

#include <functional>
#include <memory>

namespace ua::detail
{

/// Produces a Variable's whole Value for one read; answers once.
using WholeValueRead =
  std::function<void(const ValueSource::ReadContext&, std::function<void(DataValueResult)>)>;

/// A source for the SDK's own Variables whose read produces the whole Value: the source applies each read's
/// IndexRange to it (`index_range_utils::apply_to_value`), as a source must (NR-11 rule 3). With no @p write
/// the source is read-only.
std::shared_ptr<ValueSource> whole_value_source(
  WholeValueRead read, ValueSource::WriteValueHandler write = {});

}  // namespace ua::detail
