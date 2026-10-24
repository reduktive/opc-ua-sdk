// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODE_ID_VALIDATION_H
#define UA_NODE_ID_VALIDATION_H

#include <cstddef>
#include "ua_node_id.h"

namespace ua::detail
{

inline constexpr size_t maxNodeIdStringIdentifierLength{4096};
inline constexpr size_t maxNodeIdOpaqueIdentifierLength{4096};

struct NodeIdStructuralValidation
{
  bool isValid{true};
  bool encodingIsValid{true};
  size_t identifierLength{0};
  size_t maximumIdentifierLength{0};
};

NodeIdStructuralValidation validate_node_id_structure(const NodeId& nodeId) noexcept;

}  // namespace ua::detail

#endif  // UA_NODE_ID_VALIDATION_H
