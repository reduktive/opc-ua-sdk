// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_CONTINUATION_POINT_H
#define UA_DATA_TYPE_CONTINUATION_POINT_H

#include "ua_includes.h"

#include "ua_byte_string.h"

namespace ua
{

/// OPC UA ContinuationPoint simple data type.
/// @ingroup ua_data_types
using ContinuationPoint = ByteString;

}  // namespace ua

#endif  // !UA_DATA_TYPE_CONTINUATION_POINT_H
