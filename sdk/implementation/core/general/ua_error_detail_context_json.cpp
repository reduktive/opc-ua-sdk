// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_error_detail.h"

#include <boost/json.hpp>

namespace ua::detail
{

namespace
{

// Marker key + version: lets the decoder distinguish our structured payload from
// arbitrary vendor AdditionalInfo text. Bump the version if the schema changes.
constexpr std::string_view markerKey = "$uactx";
constexpr int formatVersion = 1;

// Defensive bounds on decode (the input is wire-sourced and may be hostile).
constexpr std::size_t maxParseLength = static_cast<std::size_t>(256) * 1024;  // skip parsing oversized blobs
constexpr std::size_t maxContextEntries = 128;  // cap discrete facts per layer
constexpr std::size_t maxKeyLength = 256;  // cap a single key (symmetric with value cap)
constexpr std::size_t maxValueLength = static_cast<std::size_t>(8) * 1024;  // cap a single rendered value

std::string to_std_string(const boost::json::string& s)
{
  return std::string{s.data(), s.size()};
}

}  // namespace

std::string make_additional_info(const ErrorDetail& detail)
{
  // No structured facts: keep the plain extended prose (human-readable for any
  // client; nothing to preserve as discrete keys).
  if (detail.context.empty())
  {
    return detail.detail;
  }

  boost::json::object root;
  root[markerKey] = formatVersion;
  if (!detail.detail.empty())
  {
    root["detail"] = detail.detail;
  }

  // ctx is an ARRAY of [key, value] pairs, not a JSON object: it mirrors the
  // ordered std::vector<NamedValue> exactly, preserving insertion order AND any
  // duplicate keys (a JSON object would silently collapse duplicates last-wins).
  // Boost.JSON escapes losslessly (handles ';' '=' '"' newlines, unicode).
  boost::json::array ctx;
  for (const auto& fact : detail.context)
  {
    ctx.push_back(boost::json::array{fact.key, fact.value});
  }
  root["ctx"] = std::move(ctx);

  return boost::json::serialize(root);
}

void parse_additional_info(std::string_view additionalInfo, ErrorDetail& out)
{
  // Fast reject: empty, oversized, or not a JSON object -> treat as opaque prose.
  if (additionalInfo.empty() || additionalInfo.size() > maxParseLength || additionalInfo.front() != '{')
  {
    out.detail.assign(additionalInfo);
    return;
  }

  boost::system::error_code ec;
  const boost::json::value parsed = boost::json::parse(additionalInfo, ec);
  if (ec || !parsed.is_object())
  {
    out.detail.assign(additionalInfo);  // not valid JSON -> opaque
    return;
  }

  const boost::json::object& root = parsed.get_object();
  const boost::json::value* marker = root.if_contains(markerKey);
  if (marker == nullptr || !marker->is_int64())
  {
    out.detail.assign(additionalInfo);  // JSON, but not our marker-tagged payload -> opaque
    return;
  }
  // The marker is a version int. The format evolves additively, so we best-effort
  // parse the fields we know ("detail", "ctx") regardless of version and ignore the
  // rest. A future version that needed different handling would gate on the value here.

  // Our marker is present: this call fully defines the output, so overwrite both
  // fields (do not leave stale data if "detail"/"ctx" are absent).
  out.detail.clear();
  out.context.clear();

  if (const auto* d = root.if_contains("detail"); d != nullptr && d->is_string())
  {
    out.detail = to_std_string(d->get_string());
  }

  if (const auto* c = root.if_contains("ctx"); c != nullptr && c->is_array())
  {
    const boost::json::array& ctx = c->get_array();
    out.context.reserve(std::min(ctx.size(), maxContextEntries));
    for (const auto& element : ctx)
    {
      if (out.context.size() >= maxContextEntries)
      {
        break;
      }
      if (!element.is_array())
      {
        continue;
      }
      const boost::json::array& pair = element.get_array();
      if (pair.size() != 2 || !pair[0].is_string() || !pair[1].is_string())
      {
        continue;
      }
      std::string key = to_std_string(pair[0].get_string());
      if (key.size() > maxKeyLength)
      {
        key.resize(maxKeyLength);
      }
      std::string value = to_std_string(pair[1].get_string());
      if (value.size() > maxValueLength)
      {
        value.resize(maxValueLength);
      }
      out.context.push_back(NamedValue{std::move(key), std::move(value)});
    }
  }
}

}  // namespace ua::detail
