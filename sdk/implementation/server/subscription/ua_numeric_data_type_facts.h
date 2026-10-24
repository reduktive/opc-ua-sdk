// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NUMERIC_DATA_TYPE_FACTS_H
#define UA_NUMERIC_DATA_TYPE_FACTS_H

#include "ua_address_space.h"
#include "ua_node_id.h"
#include "ua_request_info.h"

#include <cstddef>
#include <functional>
#include <optional>
#include <vector>

namespace ua::server
{

/// The deepest DataType supertype chain @ref numeric_data_type_facts climbs; a chain still undecided there is
/// not refused. The namespace-0 DataType tree is a handful of levels deep, so the bound only stops a cycle.
inline constexpr std::size_t maxNumericDataTypeDepth = 64;

/// What the namespace-0 DataType @p type says about AbsoluteDeadband without asking its namespace: true for
/// SByte to Double, Number, Integer and UInteger (Number's subtree), false for the other DataTypes whose
/// numeric identifier is from 1 to 28 except BaseDataType (each a direct subtype of BaseDataType), and
/// `nullopt` for every other type, BaseDataType included.
std::optional<bool> builtin_numeric_data_type(const NodeId& type) noexcept;

/// Which of @p types are known to lie outside the Number subtree, for the AbsoluteDeadband check of
/// CreateMonitoredItems and ModifyMonitoredItems (OPC 10000-4 7.22.2: an AbsoluteDeadband "applies only to
/// Variables with any Number data type"). Asked once per request, for the distinct DataTypes the request's
/// Variables declare (NR-24 rule 1).
///
/// A type @ref builtin_numeric_data_type decides costs no call. The others are looked up with one lookup per
/// namespace and their supertype chains walked together (@ref walk_supertypes), each chain decided at the
/// first type the table decides, and refused when it reaches BaseDataType after at least one step. A type
/// that is BaseDataType itself, a lookup that is not Good, a chain without a supertype and a chain that
/// fails or climbs past @ref maxNumericDataTypeDepth are not refused: a type that cannot be decided may hold
/// numbers.
///
/// @param addressSpace The address space the types are looked up in.
/// @param request      The request served.
/// @param types        The DataTypes; a null NodeId is not refused.
/// @param done         One answer per type, in order, true when the type is known not to be numeric;
///                     called once, and must not throw.
void numeric_data_type_facts(AddressSpace addressSpace, RequestInfo request, std::vector<NodeId> types,
  std::function<void(std::vector<bool>)> done) noexcept;

}  // namespace ua::server

#endif  // !UA_NUMERIC_DATA_TYPE_FACTS_H
