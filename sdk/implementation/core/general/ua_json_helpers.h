// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_JSON_HELPERS_H
#define UA_JSON_HELPERS_H

#include "ua_application_configuration.h"
#include "ua_application_overrides.h"

#include <boost/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace ua::json_helpers
{

[[nodiscard]] inline const boost::json::object& as_object(const boost::json::value& v)
{
  return v.as_object();
}

[[nodiscard]] inline boost::json::object& as_object(boost::json::value& v)
{
  return v.as_object();
}

template<class T>
[[nodiscard]] inline T required(const boost::json::object& obj, const char* key)
{
  return boost::json::value_to<T>(obj.at(key));
}

template<class T>
[[nodiscard]] inline std::optional<T> optional(const boost::json::object& obj, const char* key)
{
  const auto it = obj.find(key);
  if (it == obj.end())
  {
    return std::nullopt;
  }

  return boost::json::value_to<T>(it->value());
}

template<class T>
inline void emit_optional(boost::json::object& obj, const char* key, const std::optional<T>& v)
{
  if (!v)
  {
    return;
  }

  obj.emplace(key, boost::json::value_from(*v));
}

template<class T>
inline void emit(boost::json::object& obj, const char* key, const T& v)
{
  obj.emplace(key, boost::json::value_from(v));
}

[[nodiscard]] inline boost::json::value parse_json(std::string_view json)
{
  return boost::json::parse(json);
}

[[nodiscard]] std::string pretty_json(const boost::json::value& v);

// ApplicationConfig component conversion helpers (Boost.JSON hidden behind .cpp APIs).
[[nodiscard]] boost::json::value to_json_value(const ua::ApplicationConfig::ApplicationDescriptionPart& part);
[[nodiscard]] ua::ApplicationConfig::ApplicationDescriptionPart application_description_part_from_json(
  const boost::json::value& v);

[[nodiscard]] boost::json::value to_json_value(const ua::ApplicationConfig::StackLimits& limits);
[[nodiscard]] ua::ApplicationConfig::StackLimits stack_limits_from_json(const boost::json::value& v);

[[nodiscard]] boost::json::value to_json_value(const ua::ApplicationConfig::FileTrustListConfig& cfg);
[[nodiscard]] ua::ApplicationConfig::FileTrustListConfig file_trust_list_configuration_from_json(
  const boost::json::value& v);

// Higher-level config conversions used by multiple config-file implementations.
// These are implementation-only helpers (Boost.JSON stays out of public headers).
[[nodiscard]] boost::json::value to_json_value(const ua::ApplicationConfig& cfg);
[[nodiscard]] ua::ApplicationConfig application_configuration_from_json(const boost::json::value& v);

[[nodiscard]] boost::json::value to_json_value(const ua::ApplicationOverrides& overrides);
[[nodiscard]] ua::ApplicationOverrides application_overrides_from_json(const boost::json::value& v);

}  // namespace ua::json_helpers

#endif  // UA_JSON_HELPERS_H
