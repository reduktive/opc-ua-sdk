// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_reference_identity.h"

#include "ua_error_detail.h"
#include "ua_reference_type_model.h"
#include "ua_to_string.h"

#include <cstddef>
#include <unordered_map>

namespace ua::reference_identity
{

namespace
{

/// How one Reference of an add is identified: the first Reference of the add it is the same Reference as
/// (itself when none before it is), and the held Reference its group is the same Reference as (null when
/// none).
struct Match
{
  std::size_t first{0};
  const Reference* held{nullptr};
};

std::vector<Match> match(std::span<const Reference> held, std::span<const Reference> added)
{
  std::vector<Match> result(added.size());
  // The first member of each group, by the NodeId of its target.
  std::unordered_map<NodeId, std::vector<std::size_t>> byTarget;
  byTarget.reserve(added.size());
  for (std::size_t index = 0; index < added.size(); ++index)
  {
    result[index].first = index;
    auto& sameTarget = byTarget[added[index].target_id().node_id()];
    for (const std::size_t earlier : sameTarget)
    {
      if (added[index].identifies_same_reference_as(added[earlier]))
      {
        result[index].first = earlier;
        break;
      }
    }
    if (result[index].first == index)
    {
      sameTarget.push_back(index);
    }
  }
  for (const Reference& reference : held)
  {
    const auto found = byTarget.find(reference.target_id().node_id());
    if (found == byTarget.end())
    {
      continue;
    }
    for (const std::size_t index : found->second)
    {
      if (result[index].held == nullptr && added[index].identifies_same_reference_as(reference))
      {
        result[index].held = &reference;
      }
    }
  }
  for (auto& entry : result)
  {
    entry.held = result[entry.first].held;
  }
  return result;
}

}  // namespace

Result<std::vector<Reference>> references_to_add(
  std::span<const Reference> held, std::span<const Reference> added)
{
  const auto matches = match(held, added);
  // For each group not held, by its first member: the member chosen so far, the most derived type seen.
  std::vector<const Reference*> chosen(added.size(), nullptr);
  for (std::size_t index = 0; index < added.size(); ++index)
  {
    const Reference& requested = added[index];
    if (const Reference* heldReference = matches[index].held)
    {
      if (!held_as_requested(requested, *heldReference))
      {
        return conflicting_type_refusal(requested, *heldReference);
      }
      continue;
    }
    const Reference*& current = chosen[matches[index].first];
    if (current == nullptr || held_as_requested(requested, *current))
    {
      current = current == nullptr ? &requested : current;
      continue;
    }
    // More derived than the member chosen, which is more derived than every member before it: a subtype of
    // all.
    if (held_as_requested(*current, requested))
    {
      current = &requested;
      continue;
    }
    return conflicting_type_refusal(requested, *current);
  }
  std::vector<Reference> toAdd;
  toAdd.reserve(added.size());
  for (std::size_t index = 0; index < added.size(); ++index)
  {
    if (matches[index].first == index && matches[index].held == nullptr)
    {
      toAdd.push_back(*chosen[index]);
    }
  }
  return toAdd;
}

std::vector<bool> held_or_repeated(std::span<const Reference> held, std::span<const Reference> added)
{
  const auto matches = match(held, added);
  std::vector<bool> result(matches.size(), false);
  for (std::size_t index = 0; index < matches.size(); ++index)
  {
    result[index] = matches[index].first != index || matches[index].held != nullptr;
  }
  return result;
}

bool held_as_requested(const Reference& requested, const Reference& identified) noexcept
{
  const NodeId& requestedType = requested.type_id();
  return identified.type_id() == requestedType ||
         reference_type_may_match_hint(identified.type_id(), std::span<const NodeId>{&requestedType, 1});
}

StatusCode conflicting_type_refusal(const Reference& requested, const Reference& identified)
{
  return StatusCode{Status::BadDuplicateReferenceNotAllowed,
    ErrorDetail::build("DuplicateReferenceOfAnotherType",
      "The same Reference is held, or asked for twice, with a type that is neither the one asked for nor a "
      "subtype of it",
      "NodeAccessor")
      .context(ContextKeys::typeActual, identified.type_id())
      .context(ContextKeys::typeExpected, requested.type_id())
      .context(ContextKeys::nodeId, requested.target_id().node_id())};
}

}  // namespace ua::reference_identity
