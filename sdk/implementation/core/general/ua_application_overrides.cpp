// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_application_overrides.h"

#include "ua_json_helpers.h"

namespace ua
{
ApplicationConfig apply_overrides(ApplicationConfig base, const ApplicationOverrides& overrides)
{
  if (overrides.applicationDescriptionPart)
  {
    base.application_description_part() = *overrides.applicationDescriptionPart;
  }
  if (overrides.stackLimits)
  {
    base.stack_limits() = *overrides.stackLimits;
  }
  if (overrides.fileTrustListConfiguration)
  {
    base.file_trust_list_configuration() = *overrides.fileTrustListConfiguration;
  }

  if (overrides.defaultLocale)
  {
    base.defaultLocale = *overrides.defaultLocale;
  }
  if (overrides.allowInsecureEndpoints)
  {
    base.allowInsecureEndpoints = *overrides.allowInsecureEndpoints;
  }
  if (overrides.allowDeprecatedSecurityPolicies)
  {
    base.allowDeprecatedSecurityPolicies = *overrides.allowDeprecatedSecurityPolicies;
  }
  if (overrides.decodeWorkLimit)
  {
    base.execution_limits().decodeWorkLimit = *overrides.decodeWorkLimit;
  }
  if (overrides.decodeRecursionDepthLimit)
  {
    base.execution_limits().decodeRecursionDepthLimit = *overrides.decodeRecursionDepthLimit;
  }
  if (overrides.instantiationDepthLimit)
  {
    base.execution_limits().instantiationDepthLimit = *overrides.instantiationDepthLimit;
  }
  if (overrides.loopLimit)
  {
    base.execution_limits().loopLimit = *overrides.loopLimit;
  }

  base.validate();
  return base;
}

std::string ApplicationOverrides::to_json_string(bool pretty) const
{
  const boost::json::value v = ua::json_helpers::to_json_value(*this);
  return pretty ? ua::json_helpers::pretty_json(v) : boost::json::serialize(v);
}

ApplicationOverrides ApplicationOverrides::from_json_string(std::string_view json)
{
  const auto v = ua::json_helpers::parse_json(json);
  return ua::json_helpers::application_overrides_from_json(v);
}

}  // namespace ua
