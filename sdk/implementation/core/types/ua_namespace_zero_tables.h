// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Facts of the namespace-0 type model, generated from the namespace-0 NodeSet the server loads.
///
/// The definitions are emitted by the type generator (`emit_ns0_model_tables.py`) from the NodeSet file the
/// namespace-0 byte array embeds, so they describe exactly the namespace 0 the server serves. Namespace 0
/// holds only namespace-0 NodeIds (OPC 10000-5 section 6.3.1), so each table is complete for it.

#ifndef UA_NAMESPACE_ZERO_TABLES_H
#define UA_NAMESPACE_ZERO_TABLES_H

#include <cstdint>
#include <span>

namespace ua::namespace_zero_tables
{

/// One namespace-0 ReferenceType: its numeric identifier, its supertype's (0 for References, the root),
/// and its IsAbstract Attribute.
struct ReferenceTypeRow
{
  uint32_t id;
  uint32_t supertype;
  bool isAbstract;
};

/// Every namespace-0 ReferenceType, ordered by identifier.
std::span<const ReferenceTypeRow> reference_types() noexcept;

/// The numeric identifiers of the namespace-0 VariableTypes in the BaseAnalogType, ArrayItemType,
/// MultiStateDiscreteType and MultiStateValueDiscreteType subtrees (OPC 10000-8 section 5.3), ordered.
/// The rule of OPC 10000-8 5.3 that bounds a Value write to a Variable of a Data Access type.
enum class DataAccessKind : uint8_t
{
  Analog,  ///< BaseAnalogType and ArrayItemType: InstrumentRange, else EURange.
  MultiStateDiscrete,  ///< MultiStateDiscreteType: an index into EnumStrings.
  MultiStateValueDiscrete,  ///< MultiStateValueDiscreteType: a Value of EnumValues.
};

struct DataAccessTypeRow
{
  uint32_t id;
  DataAccessKind kind;
};

/// The VariableTypes of namespace 0's Data Access subtrees with their rule, sorted by id.
std::span<const DataAccessTypeRow> data_access_variable_types() noexcept;

}  // namespace ua::namespace_zero_tables

#endif  // UA_NAMESPACE_ZERO_TABLES_H
