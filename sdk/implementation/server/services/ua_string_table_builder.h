// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STRING_TABLE_BUILDER_H
#define UA_STRING_TABLE_BUILDER_H

#include "ua_array.h"
#include "ua_string.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ua::server
{

/// Deduplicates strings and assigns zero-based indices for DiagnosticInfo string tables.
///
/// Internal to the service core - not exposed to namespace implementations or user code.
class StringTableBuilder
{
public:
  /// Returns the index for this string. If the string was seen before,
  /// returns the existing index (deduplication).
  /// Returns -1 if the input is empty (spec convention: "no string specified").
  int32_t intern(std::string_view s);

  /// Build the final string table array for the ResponseHeader.
  ua::Array<ua::String> build() const;

  /// Number of unique strings interned so far.
  size_t size() const noexcept
  {
    return mStrings.size();
  }

  /// True if no strings have been interned.
  bool empty() const noexcept
  {
    return mStrings.empty();
  }

private:
  std::vector<std::string> mStrings;
  std::unordered_map<std::string, int32_t> mIndex;
};

}  // namespace ua::server

#endif  // !UA_STRING_TABLE_BUILDER_H
