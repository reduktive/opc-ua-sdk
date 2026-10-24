// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_variant.h"

#include "ua_array.h"
#include "ua_localized_text.h"
#include "ua_ref_structure.h"
#include "ua_structure.h"

namespace ua
{

void resolve_in_variant(Variant& value, span<const LocaleId> locales)
{
  if (value.is_localized_text())
  {
    auto& text = value.as<LocalizedText>();
    text = text.resolve(locales);
    return;
  }

  if (value.is_array_of_localized_text())
  {
    auto& elements = value.as<Array<LocalizedText>>();
    for (size_t i = 0; i < elements.size(); ++i)
    {
      elements[i] = elements[i].resolve(locales);
    }
    return;
  }

  if (value.is_structure())
  {
    auto& ref = value.as<RefStructure<Structure>>();
    if (auto* structure = ref.get())
    {
      structure->resolve(locales);
    }
    return;
  }

  if (value.is_array_of_structure())
  {
    auto& elements = value.as<Array<RefStructure<Structure>>>();
    for (size_t i = 0; i < elements.size(); ++i)
    {
      if (auto* structure = elements[i].get())
      {
        structure->resolve(locales);
      }
    }
    return;
  }
}

}  // namespace ua
