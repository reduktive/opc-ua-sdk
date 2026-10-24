// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_string_table_builder.h"

namespace ua::server
{

int32_t StringTableBuilder::intern(std::string_view s)
{
  if (s.empty())
  {
    return -1;
  }

  auto key = std::string{s};
  auto it = mIndex.find(key);
  if (it != mIndex.end())
  {
    return it->second;
  }

  auto index = numeric_cast<int32_t>(mStrings.size());
  mIndex.emplace(key, index);
  mStrings.push_back(std::move(key));
  return index;
}

ua::Array<ua::String> StringTableBuilder::build() const
{
  ua::Array<ua::String> table;
  auto& payload = table.payload();
  payload.reserve(mStrings.size());

  for (const auto& s : mStrings)
  {
    payload.emplace_back(s);
  }

  return table;
}

}  // namespace ua::server
