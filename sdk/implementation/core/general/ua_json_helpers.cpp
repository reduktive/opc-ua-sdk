// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_json_helpers.h"

namespace ua::json_helpers
{

namespace
{

template<class T, class ToJson>
void emit_optional_object(
  boost::json::object& obj, const char* key, const std::optional<T>& v, ToJson&& toJson)
{
  if (!v)
  {
    return;
  }

  obj.emplace(key, toJson(*v));
}

template<class T, class FromJson>
void parse_optional_object(
  const boost::json::object& obj, const char* key, std::optional<T>& out, FromJson&& fromJson)
{
  if (const auto it = obj.find(key); it != obj.end())
  {
    out = fromJson(it->value());
  }
}

ua::ApplicationOverrides to_overrides(const ua::ApplicationConfig& cfg)
{
  ua::ApplicationOverrides overrides;
  overrides.applicationDescriptionPart = cfg.application_description_part();
  overrides.stackLimits = cfg.stack_limits();
  overrides.fileTrustListConfiguration = cfg.file_trust_list_configuration();

  overrides.defaultLocale = cfg.defaultLocale;
  overrides.allowInsecureEndpoints = cfg.allowInsecureEndpoints;
  overrides.allowDeprecatedSecurityPolicies = cfg.allowDeprecatedSecurityPolicies;
  overrides.decodeWorkLimit = cfg.execution_limits().decodeWorkLimit;
  overrides.decodeRecursionDepthLimit = cfg.execution_limits().decodeRecursionDepthLimit;
  overrides.instantiationDepthLimit = cfg.execution_limits().instantiationDepthLimit;
  overrides.loopLimit = cfg.execution_limits().loopLimit;
  return overrides;
}

}  // namespace

namespace
{

void pretty_impl(std::string& out, const boost::json::value& v, unsigned indent)
{
  constexpr unsigned indentSize = 2;

  switch (v.kind())
  {
  case boost::json::kind::object:
  {
    const auto& obj = v.get_object();
    if (obj.empty())
    {
      out += "{}";
      return;
    }
    out += "{\n";
    auto it = obj.begin();
    for (;;)
    {
      out.append(indent + indentSize, ' ');
      out += boost::json::serialize(it->key());
      out += ": ";
      pretty_impl(out, it->value(), indent + indentSize);
      if (++it == obj.end())
        break;
      out += ",\n";
    }
    out += '\n';
    out.append(indent, ' ');
    out += '}';
    return;
  }
  case boost::json::kind::array:
  {
    const auto& arr = v.get_array();
    if (arr.empty())
    {
      out += "[]";
      return;
    }
    out += "[\n";
    auto it = arr.begin();
    for (;;)
    {
      out.append(indent + indentSize, ' ');
      pretty_impl(out, *it, indent + indentSize);
      if (++it == arr.end())
        break;
      out += ",\n";
    }
    out += '\n';
    out.append(indent, ' ');
    out += ']';
    return;
  }
  default:
    out += boost::json::serialize(v);
    return;
  }
}

}  // namespace

std::string pretty_json(const boost::json::value& v)
{
  std::string result;
  pretty_impl(result, v, 0);
  result += '\n';
  return result;
}

boost::json::value to_json_value(const ua::ApplicationConfig::ApplicationDescriptionPart& part)
{
  boost::json::object obj;
  obj.emplace("ApplicationUri", boost::json::value_from(part.applicationUri));
  return obj;
}

ua::ApplicationConfig::ApplicationDescriptionPart application_description_part_from_json(
  const boost::json::value& v)
{
  const auto& obj = v.as_object();
  ua::ApplicationConfig::ApplicationDescriptionPart part;
  part.applicationUri = required<std::string>(obj, "ApplicationUri");
  return part;
}

boost::json::value to_json_value(const ua::ApplicationConfig::StackLimits& limits)
{
  boost::json::object obj;
  {
    boost::json::object cp;
    cp.emplace("MaxBufferSize", boost::json::value_from(limits.connectionProtocolLimits.maxBufferSize));
    cp.emplace("MaxMessageSize", boost::json::value_from(limits.connectionProtocolLimits.maxMessageSize));
    cp.emplace("MaxChunkCount", boost::json::value_from(limits.connectionProtocolLimits.maxChunkCount));
    obj.emplace("ConnectionProtocolLimits", std::move(cp));
  }
  obj.emplace("ConnectionProtocolTimeout", boost::json::value_from(limits.connectionProtocolTimeout.count()));
  obj.emplace("ConnectionProtocolMessageReadTimeout",
    boost::json::value_from(limits.connectionProtocolMessageReadTimeout.count()));
  obj.emplace(
    "SecureChannelMinimumLifetime", boost::json::value_from(limits.secureChannelMinimumLifetime.count()));
  obj.emplace(
    "SecureChannelMaximumLifetime", boost::json::value_from(limits.secureChannelMaximumLifetime.count()));
  obj.emplace("FirstOpnTimeout", boost::json::value_from(limits.firstOpnTimeout.count()));
  obj.emplace("SessionMinimumTimeout", boost::json::value_from(limits.sessionMinimumTimeout.count()));
  obj.emplace("SessionMaximumTimeout", boost::json::value_from(limits.sessionMaximumTimeout.count()));
  return obj;
}

ua::ApplicationConfig::StackLimits stack_limits_from_json(const boost::json::value& v)
{
  const auto& obj = v.as_object();
  ua::ApplicationConfig::StackLimits limits;
  {
    const auto& cp = obj.at("ConnectionProtocolLimits").as_object();
    limits.connectionProtocolLimits.maxBufferSize = required<uint32_t>(cp, "MaxBufferSize");
    limits.connectionProtocolLimits.maxMessageSize = required<uint32_t>(cp, "MaxMessageSize");
    limits.connectionProtocolLimits.maxChunkCount = required<uint32_t>(cp, "MaxChunkCount");
  }
  limits.connectionProtocolTimeout =
    std::chrono::seconds{required<int64_t>(obj, "ConnectionProtocolTimeout")};
  if (const auto msgRead = optional<int64_t>(obj, "ConnectionProtocolMessageReadTimeout"))
  {
    limits.connectionProtocolMessageReadTimeout = std::chrono::milliseconds{*msgRead};
  }
  limits.secureChannelMinimumLifetime =
    std::chrono::milliseconds{required<int64_t>(obj, "SecureChannelMinimumLifetime")};
  limits.secureChannelMaximumLifetime =
    std::chrono::milliseconds{required<int64_t>(obj, "SecureChannelMaximumLifetime")};
  if (const auto firstOpn = optional<int64_t>(obj, "FirstOpnTimeout"))
  {
    limits.firstOpnTimeout = std::chrono::seconds{*firstOpn};
  }
  if (const auto sessionMin = optional<int64_t>(obj, "SessionMinimumTimeout"))
  {
    limits.sessionMinimumTimeout = std::chrono::milliseconds{*sessionMin};
  }
  if (const auto sessionMax = optional<int64_t>(obj, "SessionMaximumTimeout"))
  {
    limits.sessionMaximumTimeout = std::chrono::milliseconds{*sessionMax};
  }
  return limits;
}

boost::json::value to_json_value(const ua::ApplicationConfig::FileTrustListConfig& cfg)
{
  boost::json::object obj;
  obj.emplace("DefaultApplicationGroupTrustListPath",
    boost::json::value_from(cfg.defaultApplicationGroupTrustListPath.string()));
  obj.emplace("DefaultApplicationGroupTrustListValidationOptions",
    boost::json::value_from(cfg.defaultApplicationGroupTrustListValidationOptions.as_underlying_type()));
  if (cfg.defaultUserTokenGroupTrustListPath)
  {
    obj.emplace("DefaultUserTokenGroupTrustListPath",
      boost::json::value_from(cfg.defaultUserTokenGroupTrustListPath->string()));
  }
  obj.emplace("DefaultUserTokenGroupTrustListValidationOptions",
    boost::json::value_from(cfg.defaultUserTokenGroupTrustListValidationOptions.as_underlying_type()));
  if (cfg.trustListRefreshPeriod)
  {
    obj.emplace("TrustListRefreshPeriod", boost::json::value_from(cfg.trustListRefreshPeriod->count()));
  }
  obj.emplace("StoreRejectedCertificates", boost::json::value_from(cfg.storeRejectedCertificates));
  obj.emplace(
    "MaxRejectedCertificates", boost::json::value_from(static_cast<uint64_t>(cfg.maxRejectedCertificates)));
  return obj;
}

ua::ApplicationConfig::FileTrustListConfig file_trust_list_configuration_from_json(
  const boost::json::value& v)
{
  const auto& obj = v.as_object();
  ua::ApplicationConfig::FileTrustListConfig cfg;
  cfg.defaultApplicationGroupTrustListPath =
    required<std::string>(obj, "DefaultApplicationGroupTrustListPath");
  cfg.defaultApplicationGroupTrustListValidationOptions = static_cast<ua::TrustListValidationOptions>(
    required<uint32_t>(obj, "DefaultApplicationGroupTrustListValidationOptions"));
  if (const auto userTokenPath = optional<std::string>(obj, "DefaultUserTokenGroupTrustListPath"))
  {
    cfg.defaultUserTokenGroupTrustListPath = std::filesystem::path{*userTokenPath};
  }
  cfg.defaultUserTokenGroupTrustListValidationOptions = static_cast<ua::TrustListValidationOptions>(
    required<uint32_t>(obj, "DefaultUserTokenGroupTrustListValidationOptions"));
  if (const auto refresh = optional<int64_t>(obj, "TrustListRefreshPeriod"))
  {
    cfg.trustListRefreshPeriod = std::chrono::seconds{*refresh};
  }
  if (const auto store = optional<bool>(obj, "StoreRejectedCertificates"))
  {
    cfg.storeRejectedCertificates = *store;
  }
  // Optional (back-compatible): absent keeps the default bound (100). 0 disables the bound.
  if (const auto maxRejected = optional<uint64_t>(obj, "MaxRejectedCertificates"))
  {
    cfg.maxRejectedCertificates = static_cast<size_t>(*maxRejected);
  }
  return cfg;
}

boost::json::value to_json_value(const ua::ApplicationConfig& cfg)
{
  return to_json_value(to_overrides(cfg));
}

ua::ApplicationConfig application_configuration_from_json(const boost::json::value& v)
{
  auto base = ua::ApplicationConfig::load_default();
  const auto overrides = application_overrides_from_json(v);
  return ua::apply_overrides(std::move(base), overrides);
}

boost::json::value to_json_value(const ua::ApplicationOverrides& overrides)
{
  boost::json::object obj;

  emit_optional_object(obj,
    "ApplicationDescriptionPart",
    overrides.applicationDescriptionPart,
    [](const auto& v) { return to_json_value(v); });
  emit_optional_object(
    obj, "StackLimits", overrides.stackLimits, [](const auto& v) { return to_json_value(v); });
  emit_optional_object(obj,
    "FileTrustListConfiguration",
    overrides.fileTrustListConfiguration,
    [](const auto& v) { return to_json_value(v); });

  emit_optional(obj,
    "DefaultLocale",
    overrides.defaultLocale ? std::optional<std::string>{std::string{*overrides.defaultLocale}}
                            : std::optional<std::string>{});
  emit_optional(obj, "AllowInsecureEndpoints", overrides.allowInsecureEndpoints);
  emit_optional(obj, "AllowDeprecatedSecurityPolicies", overrides.allowDeprecatedSecurityPolicies);
  emit_optional(obj, "DecodeWorkLimit", overrides.decodeWorkLimit);
  emit_optional(obj, "DecodeRecursionDepthLimit", overrides.decodeRecursionDepthLimit);
  emit_optional(obj, "InstantiationDepthLimit", overrides.instantiationDepthLimit);
  emit_optional(obj, "LoopLimit", overrides.loopLimit);
  return obj;
}

ua::ApplicationOverrides application_overrides_from_json(const boost::json::value& v)
{
  const auto& obj = v.as_object();
  ua::ApplicationOverrides overrides;

  parse_optional_object(obj,
    "ApplicationDescriptionPart",
    overrides.applicationDescriptionPart,
    [](const auto& jv) { return application_description_part_from_json(jv); });
  parse_optional_object(
    obj, "StackLimits", overrides.stackLimits, [](const auto& jv) { return stack_limits_from_json(jv); });
  parse_optional_object(obj,
    "FileTrustListConfiguration",
    overrides.fileTrustListConfiguration,
    [](const auto& jv) { return file_trust_list_configuration_from_json(jv); });

  if (const auto s = optional<std::string>(obj, "DefaultLocale"))
  {
    overrides.defaultLocale = ua::LocaleId{*s};
  }
  overrides.allowInsecureEndpoints = optional<bool>(obj, "AllowInsecureEndpoints");
  overrides.allowDeprecatedSecurityPolicies = optional<bool>(obj, "AllowDeprecatedSecurityPolicies");
  overrides.decodeWorkLimit = optional<size_t>(obj, "DecodeWorkLimit");
  overrides.decodeRecursionDepthLimit = optional<size_t>(obj, "DecodeRecursionDepthLimit");
  overrides.instantiationDepthLimit = optional<size_t>(obj, "InstantiationDepthLimit");
  overrides.loopLimit = optional<size_t>(obj, "LoopLimit");
  return overrides;
}

}  // namespace ua::json_helpers
