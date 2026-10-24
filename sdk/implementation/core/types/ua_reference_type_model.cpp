// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_reference_type_model.h"

#include "ua_namespace_zero_tables.h"

#include <algorithm>

namespace ua
{
namespace
{

using namespace_zero_tables::ReferenceTypeRow;

/// The row of namespace-0 ReferenceType @p id, or null when namespace 0 has none.
const ReferenceTypeRow* find_row(uint32_t id) noexcept
{
  const auto rows = namespace_zero_tables::reference_types();
  const auto found = std::ranges::lower_bound(
    rows, id, std::ranges::less{}, [](const ReferenceTypeRow& row) { return row.id; });
  return (found != rows.end() && found->id == id) ? &*found : nullptr;
}

/// The row of @p referenceType when it is a namespace-0 ReferenceType, or null.
const ReferenceTypeRow* find_row(const NodeId& referenceType) noexcept
{
  if (referenceType.namespace_index() != 0 || !referenceType.is_numeric())
  {
    return nullptr;
  }
  return find_row(referenceType.identifier().get_numeric());
}

}  // namespace

NodeId reference_identity_type(const NodeId& referenceType)
{
  const ReferenceTypeRow* row = find_row(referenceType);
  if (row == nullptr || row->isAbstract)
  {
    return referenceType;
  }
  // Up while the supertype is concrete: the last concrete type is the base the subtypes are equal to.
  while (row->supertype != 0)
  {
    const ReferenceTypeRow* supertype = find_row(row->supertype);
    if (supertype == nullptr || supertype->isAbstract)
    {
      break;
    }
    row = supertype;
  }
  return NodeId{0, row->id};
}

bool reference_type_may_match_hint(const NodeId& referenceType, std::span<const NodeId> hint) noexcept
{
  if (hint.empty())
  {
    return true;
  }
  const ReferenceTypeRow* row = find_row(referenceType);
  if (row == nullptr)
  {
    return true;
  }
  // The type and each of its supertypes, against every hinted namespace-0 type. The hierarchy is a tree of
  // a few levels, and the generator refuses a table with a cycle in it.
  for (const ReferenceTypeRow* current = row; current != nullptr;
       current = current->supertype != 0 ? find_row(current->supertype) : nullptr)
  {
    const bool hinted = std::ranges::any_of(hint,
      [current](const NodeId& wanted)
      {
        return wanted.namespace_index() == 0 && wanted.is_numeric() &&
               wanted.identifier().get_numeric() == current->id;
      });
    if (hinted)
    {
      return true;
    }
  }
  return false;
}

}  // namespace ua
