// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Mandatory write invariants defined by the OPC UA Information Model.

#ifndef UA_INFORMATION_MODEL_PAIRS_H
#define UA_INFORMATION_MODEL_PAIRS_H

#include "ua_address_space.h"
#include "ua_node_accessor.h"
#include "ua_qualified_name.h"
#include "ua_result.h"

#include <cstddef>
#include <functional>

namespace ua::server
{

/// Whether a Value write to a Variable with this BrowseName can break a paired-array invariant of the
/// information model, so that the Write service checks it (NR-34 rule 1, NR-24 step 5e): 0:Selections,
/// 0:SelectionDescriptions and 0:EnumValues.
bool is_information_model_pair(const QualifiedName& browseName);

/// Checks a whole-array Value write of @p proposedSize elements to @p variable, whose BrowseName
/// @ref is_information_model_pair accepts, against its pair: a SelectionList's Selections and
/// SelectionDescriptions keep their length, and an EnumValues array keeps the row count of its
/// EnumDictionaryEntries. A Variable whose owner is not of the type the pair belongs to is not checked.
///
/// @param done Called once: Good, or the refusal (`Bad_OutOfRange` with the sizes in the ErrorDetail, or the
///             status of a read the check needed).
void check_information_model_pair_async(AddressSpace addressSpace, NodeAccessor variable,
  std::size_t proposedSize, std::function<void(VoidResult)> done) noexcept;

}  // namespace ua::server

#endif  // !UA_INFORMATION_MODEL_PAIRS_H
