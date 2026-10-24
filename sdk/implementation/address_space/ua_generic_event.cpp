// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_generic_event.h"

#include <algorithm>
#include <memory>
#include "ua_data_value.h"

namespace ua
{

std::unique_ptr<BaseEvent> GenericEvent::clone() const
{
  return std::make_unique<GenericEvent>(*this);
}

void GenericEvent::set_field(std::vector<QualifiedName> browsePath, Variant value)
{
  // Update existing entry if browse path matches, otherwise add new.
  for (auto& [path, existing_value] : mExtraFields)
  {
    if (path.size() == browsePath.size() && std::equal(path.begin(), path.end(), browsePath.begin()))
    {
      existing_value = std::move(value);
      return;
    }
  }
  mExtraFields.emplace_back(std::move(browsePath), std::move(value));
}

Variant GenericEvent::resolve_field(std::span<const QualifiedName> browsePath) const
{
  // Check base fields first.
  auto result = resolve_base_field(browsePath);
  if (!result.empty())
    return result;

  // Check extension fields.
  for (const auto& [path, value] : mExtraFields)
  {
    if (path.size() == browsePath.size() && std::equal(path.begin(), path.end(), browsePath.begin()))
    {
      return value;
    }
  }

  return Variant{};
}

}  // namespace ua
