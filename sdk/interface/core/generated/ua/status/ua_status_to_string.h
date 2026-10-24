// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Auto-generated - do not edit.
#ifndef UA_STATUS_TO_STRING_H
#define UA_STATUS_TO_STRING_H

#include <string>
#include <string_view>
#include "ua_status.h"

namespace ua
{

std::string to_string(Status status);

/// The specification's description of @p status (OPC Foundation StatusCode.csv), or empty for a
/// code the table does not know. Fixed, public text: safe to send to a peer.
std::string_view description(Status status);

}  // namespace ua

#endif  // UA_STATUS_TO_STRING_H
