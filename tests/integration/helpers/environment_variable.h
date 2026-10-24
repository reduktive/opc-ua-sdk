// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_ENVIRONMENT_VARIABLE_H
#define UA_TEST_ENVIRONMENT_VARIABLE_H

#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>

namespace ua::test_helpers
{

/// Reads a non-empty process environment variable without using MSVC's deprecated `getenv` API.
///
/// This helper is test/example infrastructure, not SDK API. An unset or empty variable returns
/// `std::nullopt`. A concurrent environment mutation that changes the required Windows buffer size
/// is also treated as absent; callers already have an explicit fallback for that case.
inline std::optional<std::string> read_environment_variable(std::string_view name)
{
  const std::string key{name};
#if defined(_MSC_VER)
  std::size_t requiredSize = 0;
  if (::getenv_s(&requiredSize, nullptr, 0, key.c_str()) != 0 || requiredSize <= 1)
    return std::nullopt;

  std::string value(requiredSize, '\0');
  if (::getenv_s(&requiredSize, value.data(), value.size(), key.c_str()) != 0 || requiredSize <= 1)
    return std::nullopt;

  value.resize(requiredSize - 1);
  return value;
#else
  if (const auto value = std::getenv(key.c_str()); value != nullptr && value[0] != '\0')
    return std::string{value};
  return std::nullopt;
#endif
}

}  // namespace ua::test_helpers

#endif  // UA_TEST_ENVIRONMENT_VARIABLE_H
